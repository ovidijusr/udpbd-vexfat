use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write}, 
    path::{Path, PathBuf, MAIN_SEPARATOR_STR},
};

use vexfatbd::{VirtualExFatBlockDevice, heap::DirectoryEntry, data_region::file::FileNameDirectoryEntry};
use walkdir::WalkDir;

use crate::{
    protocol::RDMA_MAX_PAYLOAD,
    utils::{relative_path_from_common_root, unsigned_align_to, unsigned_rounded_up_div},
    Args,
};

const BYTES_PER_SECTOR_SHIFT: u8 = 9; // 512 bytes
const SECTORS_PER_FILE: u32 = 400; // 200KB generous allocation per file

#[derive(Debug)]
pub enum WriteError {
    ReadOnlyFile(PathBuf),
    OutOfSpace,
    IoError(io::Error),
    InvalidSector(u32),
}

impl From<io::Error> for WriteError {
    fn from(err: io::Error) -> Self {
        WriteError::IoError(err)
    }
}

pub struct VexFat {
    vexfat: VirtualExFatBlockDevice,
    sector_count: u32,
    pub block_shift: u8,
    pub block_size: u16,
    pub blocks_per_packet: u16,
    pub blocks_per_socket: u16,
    
    // Write support fields
    write_cache: HashMap<u32, Vec<u8>>,
    sector_to_file: HashMap<u32, PathBuf>,
    file_to_start_sector: HashMap<PathBuf, u32>,
    file_write_offsets: HashMap<PathBuf, u64>,
    writeable_paths: HashSet<PathBuf>,
    writeable_dirs: HashSet<PathBuf>,
    dirty_sectors: HashSet<u32>,
    current_write_sector: u32,
    current_write_offset_in_sector: u32,
    
    // Directory entry parsing for filename extraction
    sector_to_filename: HashMap<u32, String>, // Persistent sector -> filename mapping
    directory_entry_buffer: Vec<u8>,
    next_available_sector: u32, // Track next sector to allocate for new files
    
    // Directory cluster mapping for virtual filesystem integration
    dir_to_cluster: HashMap<PathBuf, u32>,
    
    // Track active cache file being written
    active_cache_file: Option<(u32, PathBuf)>, // (start_sector, file_path)

    // Newly created files during a write sequence to be added to virtual FS on flush
    newly_created_files: Vec<PathBuf>,
}

impl VexFat {
    /// Parse directory entries to extract filenames from FileNameDirectoryEntry structures
    fn parse_directory_entries(&mut self, data: &[u8]) {
        println!("=== PARSING DIRECTORY ENTRIES ===");
        println!("Input data: {} bytes", data.len());
        println!("Raw data (first 128 bytes): {:02x?}", &data[0..std::cmp::min(128, data.len())]);
        
        // Add data to the buffer
        self.directory_entry_buffer.extend_from_slice(data);
        println!("Buffer now contains {} bytes", self.directory_entry_buffer.len());
        
        // Directory entries are 32 bytes each
        let mut entry_count = 0;
        while self.directory_entry_buffer.len() >= 32 {
            let entry_bytes = &self.directory_entry_buffer[0..32];
            entry_count += 1;
            
            // Skip empty entries (all zeros) - these cause spam
            if entry_bytes.iter().all(|&b| b == 0) {
                self.directory_entry_buffer.drain(0..32);
                continue;
            }
            
            // Try to parse as directory entry
            if let Some(entry) = DirectoryEntry::new_from_bytes(entry_bytes) {
                match entry {
                    DirectoryEntry::FileName(file_name_entry) => {
                        // Extract filename from FileNameDirectoryEntry  
                        let filename = Self::extract_filename_from_entry(&file_name_entry);
                        if !filename.is_empty() {
                            println!("ALLOCATING SECTOR BLOCK FOR FILENAME: {}", filename);
                            self.allocate_sector_block_for_file(&filename);
                        }
                    }
                    DirectoryEntry::File(_) => {
                        // File entry found
                    }
                    DirectoryEntry::StreamExtension(_) => {
                        // Stream extension found
                    }
                    DirectoryEntry::VolumeLabel(_) => {
                        println!("Found VolumeLabel directory entry");
                    }
                    DirectoryEntry::AllocationBitmap(_) => {
                        println!("Found AllocationBitmap directory entry");
                    }
                    DirectoryEntry::UpcaseTable(_) => {
                        println!("Found UpcaseTable directory entry");
                    }
                    _ => {
                        // Other entry types
                    }
                }
            }
            
            // Remove processed entry from buffer
            self.directory_entry_buffer.drain(0..32);
        }
        
        println!("Finished processing {} directory entries", entry_count);
        println!("Remaining buffer: {} bytes", self.directory_entry_buffer.len());
        println!("Sector-to-filename mappings: {}", self.sector_to_filename.len());
        println!("=== END DIRECTORY ENTRY PARSING ===\n");
    }
    
    /// Extract filename string from FileNameDirectoryEntry
    fn extract_filename_from_entry(entry: &FileNameDirectoryEntry) -> String {
        // Convert UTF-16 filename to UTF-8 string
        let filename_chars: Vec<u16> = entry.file_name
            .iter()
            .take_while(|&&c| c != 0) // Stop at null terminator
            .copied()
            .collect();
        
        String::from_utf16(&filename_chars).unwrap_or_default()
    }

    /// Allocate a block of sectors for a filename (400 sectors = 200KB)
    fn allocate_sector_block_for_file(&mut self, filename: &str) {
        let start_sector = self.next_available_sector;
        let end_sector = start_sector + SECTORS_PER_FILE;
        
        println!("=== ALLOCATING SECTOR BLOCK ===");
        println!("Filename: {}", filename);
        println!("Sector range: {} - {}", start_sector, end_sector - 1);
        println!("Size: {} sectors ({} KB)", SECTORS_PER_FILE, SECTORS_PER_FILE / 2);
        
        // Map all sectors in the block to this filename
        for sector in start_sector..end_sector {
            self.sector_to_filename.insert(sector, filename.to_string());
        }
        
        // Update next available sector
        self.next_available_sector = end_sector;
        
        println!("Next available sector: {}", self.next_available_sector);
        println!("=== END SECTOR ALLOCATION ===\n");
    }

    /// Get filename for a specific sector
    fn get_filename_for_sector(&self, sector: u32) -> Option<&String> {
        self.sector_to_filename.get(&sector)
    }

    /// Determine filename from write context and data preview
    fn determine_filename_from_context(&self, lookahead: &[u8]) -> String {
        // Content-based filename detection
        if lookahead.len() >= 4 {
            match &lookahead[0..4] {
                b"NIDC" => return "cache.bin".to_string(),
                b"---\n" | b"#---" => return "global.yaml".to_string(), // YAML header
                _ => {}
            }
        }
        
        // Check for YAML content patterns
        if lookahead.len() >= 10 {
            let content_str = String::from_utf8_lossy(lookahead);
            if content_str.contains("yaml") || content_str.contains("config") {
                return "global.yaml".to_string();
            }
        }
        
        // Binary data might be lastTitle.bin
        if lookahead.len() >= 8 && lookahead.iter().any(|&b| b == 0) {
            return "lastTitle.bin".to_string();
        }
        
        // Fallback sequential naming
        "nhddl_file.bin".to_string()
    }

    /// Create a file dynamically during write operations  
    fn create_file_dynamically(&mut self, sector: u32, writable_dir: &Path, lookahead: &[u8]) -> io::Result<PathBuf> {
        println!("=== DYNAMIC FILE CREATION ===");
        println!("Sector: {}", sector);
        println!("Directory: {}", writable_dir.display());
        println!("Data preview: {:02x?}", &lookahead[0..std::cmp::min(32, lookahead.len())]);
        
        // Determine filename from content
        let filename = self.determine_filename_from_context(lookahead);
        println!("Detected filename: {}", filename);
        
        // Align sector to block boundary for clean allocation
        let start_sector = (sector / SECTORS_PER_FILE) * SECTORS_PER_FILE;
        if start_sector < self.next_available_sector {
            // Use next available sector if alignment would conflict
            self.next_available_sector = std::cmp::max(self.next_available_sector, sector);
            self.allocate_sector_block_for_file(&filename);
        } else {
            // Use aligned sector
            self.next_available_sector = start_sector;
            self.allocate_sector_block_for_file(&filename);
        }
        
        // Create file path
        let file_path = writable_dir.join(&filename);
        println!("Creating file: {}", file_path.display());
        
        // Create actual file on host filesystem
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::File::create(&file_path)?;
        
        // Add to virtual filesystem mappings  
        self.sector_to_file.insert(sector, file_path.clone());
        self.writeable_paths.insert(file_path.clone());
        
        // Track as newly created
        self.newly_created_files.push(file_path.clone());
        
        println!("File created successfully: {}", file_path.display());
        println!("=== END DYNAMIC FILE CREATION ===\n");
        
        Ok(file_path)
    }
    fn is_writeable_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("art") || path_str.contains("cfg") || 
        path_str.contains("cache") || path_str.contains("save") ||
        path_str.contains("tmp") || path_str.contains("temp") ||
        path_str.contains("nhddl")
    }

    pub fn new(args: &Args) -> Self {
        let root: std::path::PathBuf = args.root.clone();
        let prefix = match &args.prefix {
            Some(name) => name.clone(),
            None => String::new(),
        };

        for name in [
            "APPS", "ART", "CD", "CFG", "DVD", "CHT", "LNG", "THM", "VMC", "nhddl",
        ] {
            let path = root.join(name);
            if path.exists() {
                continue;
            }

            println!("Creating {}", path.display());
            fs::create_dir(path).expect("failed to create default OPL directories");
        }

        let mut total_files_bytes = 0;
        let mut total_files_count = 0;
        let mut total_dirs_count = 0;
        let mut items = Vec::new();

        for entry in WalkDir::new(&args.root)
            .min_depth(1)
            .contents_first(false)
            .sort_by_file_name()
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    eprintln!("Failed to read entry: {err}");
                    continue;
                }
            };
            let path = entry.path();

            if path.is_file() {
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(err) => {
                        eprintln!("Failed to read metadata: {err}");
                        continue;
                    }
                };

                #[cfg(target_os = "linux")]
                {
                    use std::os::unix::fs::MetadataExt;
                    total_files_bytes += metadata.size();
                }
                #[cfg(target_os = "macos")]
                {
                    use std::os::unix::fs::MetadataExt;
                    total_files_bytes += metadata.size();
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::fs::MetadataExt;
                    total_files_bytes += metadata.file_size();
                }

                total_files_count += 1;
            } else {
                total_dirs_count += 1;
            }

            items.push((path.to_owned(), path.is_file()));
        }

        let sector_size = 1 << BYTES_PER_SECTOR_SHIFT;
        let sectors_per_cluster_shift = 11; // 2048 sectors
        let sectors_per_cluster = 1 << sectors_per_cluster_shift;
        let bytes_per_cluster = sectors_per_cluster * sector_size;

        // Calculate clusters needed for files, with generous overhead
        let file_clusters = unsigned_rounded_up_div(total_files_bytes, bytes_per_cluster as u64);
        let metadata_clusters = 5 * (total_dirs_count + total_files_count) as u64; // Increased from 3 to 5
        let overhead_clusters = 1000; // Add 1000 clusters (~2GB) for filesystem overhead and growth
        
        let cluster_count = file_clusters + metadata_clusters + overhead_clusters;
        let cluster_count = unsigned_align_to(cluster_count, 2);
        
        println!("Filesystem sizing:");
        println!(" - Total files: {} ({} bytes)", total_files_count, total_files_bytes);
        println!(" - Total dirs: {}", total_dirs_count);
        println!(" - File clusters: {}", file_clusters);
        println!(" - Metadata clusters: {}", metadata_clusters);
        println!(" - Overhead clusters: {}", overhead_clusters);
        println!(" - Total clusters: {}", cluster_count);
        let sector_count = cluster_count * sectors_per_cluster;

        let mut vexfat = vexfatbd::VirtualExFatBlockDevice::new(
            BYTES_PER_SECTOR_SHIFT,
            sectors_per_cluster_shift,
            cluster_count as _,
        )
        .unwrap();

        println!("Mapping files");

        let prefix_cluster = match &args.prefix {
            Some(name) => vexfat.add_directory_in_root(name).unwrap(),
            None => vexfat.root_directory_cluster(),
        };
        let root_cluster = vexfat.root_directory_cluster();

        let mut dirpath_to_cluster = HashMap::from([(root.clone(), prefix_cluster)]);
    let mut sector_to_file = HashMap::new();
    let mut file_to_start_sector: HashMap<PathBuf, u32> = HashMap::new();
        let mut writeable_paths = HashSet::new();
        let mut writeable_dirs = HashSet::new();
        let mut dir_to_cluster = HashMap::new();
        
        // Initialize with root directory mapping
        dir_to_cluster.insert(root.clone(), prefix_cluster);

        for (path, is_file) in items {
            let parent = path.parent().unwrap().to_owned();
            let parent_cluster = dirpath_to_cluster.get(&parent).cloned().unwrap();

            if is_file {
        match vexfat.map_file(parent_cluster, &path) {
                    Ok(file_cluster) => {
                        // Map the file's sectors to the file path for write operations
                        // This is a simplified mapping - in a real implementation, we'd need
                        // to track the exact cluster-to-sector mappings from the vexFAT
                        let start_sector = vexfat.cluster_heap_offset() + 
                            (file_cluster.saturating_sub(2) * sectors_per_cluster as u32);
            file_to_start_sector.insert(path.clone(), start_sector);
                        
                        // Map a range of sectors for this file (simplified approach)
                        for i in 0..100 { // Map up to 100 sectors per file
                            sector_to_file.insert(start_sector + i, path.clone());
                        }
                        println!("  Mapped sectors {}-{} to {}", start_sector, start_sector + 99, path.display());
                    }
                    Err(err) => {
                        println!("! Failed to map file {}: {:?}", path.display(), err);
                    }
                }
            } else {
                let name: &str = path.file_name().unwrap().to_str().unwrap();

                // Special-case: ensure 'nhddl' exists at filesystem root even when prefix is set
                let target_parent_cluster = if name.eq_ignore_ascii_case("nhddl") {
                    root_cluster
                } else {
                    parent_cluster
                };

                match vexfat.add_directory(target_parent_cluster, name) {
                    Ok(dir_cluster) => {
                        dirpath_to_cluster.insert(path.to_owned(), dir_cluster);
                        dir_to_cluster.insert(path.clone(), dir_cluster);
                        
                        // Map writeable directories to allow new file creation
                        if Self::is_writeable_path(&path) {
                            writeable_dirs.insert(path.clone());
                            // Map a large sector range for this directory to handle new file creation
                            let dir_start_sector = vexfat.cluster_heap_offset() + 
                                (dir_cluster.saturating_sub(2) * sectors_per_cluster as u32);
                            
                            // Map many sectors for directory writes (new file creation)
                            for i in 0..10000 { // Map 10000 sectors for directory writes
                                sector_to_file.insert(dir_start_sector + i, path.clone());
                            }
                            println!("  Mapped directory sectors {}-{} to {}", 
                                dir_start_sector, dir_start_sector + 9999, path.display());
                        }
                    }
                    Err(err) => {
                        println!("! Failed to map directory {}: {:?}", path.display(), err);
                    }
                }
            }

            let relative = relative_path_from_common_root(&root, &path);
            let is_writeable = Self::is_writeable_path(&path);
            
            if is_writeable {
                writeable_paths.insert(path.clone());
                println!(" - rw:vexfat:{}{}{}", prefix, MAIN_SEPARATOR_STR, relative.display());
            } else {
                println!(" - ro:vexfat:{}{}{}", prefix, MAIN_SEPARATOR_STR, relative.display());
            }
        }

        println!("Emulating exFAT block device with write support");
        println!(" - size = {} MiB", vexfat.volume_size() / 1024 / 1024);
        println!(" - writeable paths: {}", writeable_paths.len());
        println!(" - sector mappings: {}", sector_to_file.len());

        Self {
            vexfat,
            sector_count: sector_count as u32,
            block_shift: 0,
            block_size: 0,
            blocks_per_packet: 0,
            blocks_per_socket: 0,
            
            write_cache: HashMap::new(),
            sector_to_file,
            file_to_start_sector,
            file_write_offsets: HashMap::new(),
            writeable_paths,
            writeable_dirs,
            dirty_sectors: HashSet::new(),
            current_write_sector: 0,
            current_write_offset_in_sector: 0,
            dir_to_cluster,
            sector_to_filename: HashMap::new(),
            directory_entry_buffer: Vec::new(),
            next_available_sector: 50000, // Start allocation from a high sector to avoid conflicts
            active_cache_file: None,
            newly_created_files: Vec::new(),
        }
    }

    pub fn seek(&mut self, sector: u32) -> io::Result<()> {
        let offset = u64::from(sector) * u64::from(self.sector_size());
        self.current_write_sector = sector;
    self.current_write_offset_in_sector = 0;

        self.vexfat
            .seek(std::io::SeekFrom::Start(offset))
            .map(|_| ())
    }

    // Begin a new write sequence from the client. Reset per-file streaming offsets
    // and active file so subsequent writes start from offset 0 for each target.
    pub fn begin_write_sequence(&mut self) {
        self.file_write_offsets.clear();
        self.active_cache_file = None;
        self.current_write_offset_in_sector = 0;
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.vexfat.read_exact(buf).map(|_| ())
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        println!("=== WRITE OPERATION START ===");
        println!("Buffer size: {} bytes", buf.len());
        println!("Starting sector: {}", self.current_write_sector);
        println!("Buffer data (first 64 bytes): {:02x?}", &buf[0..std::cmp::min(64, buf.len())]);
        
        // Stream the incoming bytes across sectors, writing through to host files
        let mut offset_in_buf = 0usize;
        let sector_size = self.sector_size() as usize;

        while offset_in_buf < buf.len() {
            // Determine bytes we can write into the current sector
            let space_in_sector = sector_size - self.current_write_offset_in_sector as usize;
            let to_write = (buf.len() - offset_in_buf).min(space_in_sector);

            // Resolve or create a target file for this sector
            println!("Resolving sector {} (offset {}, {} bytes)", self.current_write_sector, offset_in_buf, to_write);
            
            // Parse directory entries from ANY write that contains them (not just metadata sectors)
            let data_chunk = &buf[offset_in_buf..offset_in_buf + to_write];
            println!("Checking sector {} for directory entries - first byte: 0x{:02x}", self.current_write_sector, data_chunk[0]);
            
            if data_chunk.len() >= 32 {
                println!("Data chunk is large enough for directory entries (>= 32 bytes)");
                if data_chunk[0] == 0x85 {
                    println!("FOUND FILE DIRECTORY ENTRY (0x85) in sector {} - parsing for filename", self.current_write_sector);
                    self.parse_directory_entries(data_chunk);
                    // Directory entry sectors should NOT create actual files, they just provide metadata
                    println!("Directory entry sector - skipping file creation, just extracting filename");
                    
                    // Advance positions before continuing to avoid infinite loop
                    self.current_write_offset_in_sector += to_write as u32;
                    offset_in_buf += to_write;
                    if self.current_write_offset_in_sector as usize >= sector_size {
                        self.current_write_sector = self.current_write_sector.saturating_add(1);
                        self.current_write_offset_in_sector = 0;
                    }
                    continue; // Skip to next sector iteration
                } else if data_chunk[0] == 0xC1 {
                    println!("FOUND FILENAME DIRECTORY ENTRY (0xC1) in sector {} - parsing for filename", self.current_write_sector);
                    self.parse_directory_entries(data_chunk);
                    // Directory entry sectors should NOT create actual files, they just provide metadata  
                    println!("Directory entry sector - skipping file creation, just extracting filename");
                    
                    // Advance positions before continuing to avoid infinite loop
                    self.current_write_offset_in_sector += to_write as u32;
                    offset_in_buf += to_write;
                    if self.current_write_offset_in_sector as usize >= sector_size {
                        self.current_write_sector = self.current_write_sector.saturating_add(1);
                        self.current_write_offset_in_sector = 0;
                    }
                    continue; // Skip to next sector iteration
                } else {
                    println!("First byte 0x{:02x} is not a directory entry type we recognize", data_chunk[0]);
                }
            } else {
                println!("Data chunk too small for directory entries ({} bytes)", data_chunk.len());
            }
            
            let target_path = self.resolve_or_create_mapping_for_sector(self.current_write_sector, data_chunk)?;
            println!("Resolved to: {:?}", target_path);

            if let Some(file_path) = target_path {
                // Compute logical sequential file offset per target file
                let file_offset = {
                    let entry = self
                        .file_write_offsets
                        .entry(file_path.clone())
                        .or_insert(0);
                    let pos = *entry;
                    *entry += to_write as u64;
                    pos
                };

                // Perform write-through at computed offset
                let pre_exists = file_path.exists();
                self.extend_or_create_file_at_offset(&file_path, file_offset, &buf[offset_in_buf..offset_in_buf + to_write])?;
                if !pre_exists {
                    // Track for virtual filesystem integration on flush
                    if !self.newly_created_files.iter().any(|p| p == &file_path) {
                        self.newly_created_files.push(file_path.clone());
                    }
                }
            } else {
                // No target file: treat as metadata write (likely directory entries)
                println!("NO TARGET FILE FOUND FOR SECTOR {} - treating as metadata", self.current_write_sector);
                println!("Metadata write to sector {} ({} bytes)", self.current_write_sector, to_write);
                println!("Metadata content (first 64 bytes): {:02x?}", 
                    &buf[offset_in_buf..offset_in_buf + std::cmp::min(64, to_write)]);
                
                // Parse directory entries to extract filename information
                println!("Calling parse_directory_entries for metadata write");
                self.parse_directory_entries(&buf[offset_in_buf..offset_in_buf + to_write]);
            }

            // Advance positions
            self.current_write_offset_in_sector += to_write as u32;
            offset_in_buf += to_write;
            if self.current_write_offset_in_sector as usize >= sector_size {
                self.current_write_sector = self.current_write_sector.saturating_add(1);
                self.current_write_offset_in_sector = 0;
            }
        }

        Ok(())
    }

    pub fn sector_size(&self) -> u16 {
        self.vexfat.bytes_per_sector()
    }

    pub fn sector_count(&self) -> u32 {
        self.sector_count
    }

    pub fn set_block_shift(&mut self, shift: u8) {
        if shift == self.block_shift {
            return;
        }

        self.block_shift = shift;
        self.block_size = 1 << (shift + 2);
        self.blocks_per_packet = RDMA_MAX_PAYLOAD as u16 / self.block_size;
        self.blocks_per_socket = self.sector_size() / self.block_size;
        println!("Block size changed to {}", self.block_size);
    }

    pub fn set_block_shift_sectors(&mut self, sectors: u16) {
        // Optimize for:
        // - the least number of network packets
        // - the largest block size (faster on the PS2)
        let size = u32::from(sectors) * u32::from(self.sector_size());
        let packets_min = (size + 1440 - 1) / 1440;
        let packets_128 = (size + 1408 - 1) / 1408;
        let packets_256 = (size + 1280 - 1) / 1280;
        let packets_512 = (size + 1024 - 1) / 1024;

        let shift = {
            if packets_512 == packets_min {
                7 // 512 byte blocks
            } else if packets_256 == packets_min {
                6 // 256 byte blocks
            } else if packets_128 == packets_min {
                5 // 128 byte blocks
            } else {
                3 //  32 byte blocks
            }
        };

        self.set_block_shift(shift);
    }

    fn extend_or_create_file_at_offset(&mut self, path: &Path, offset: u64, data: &[u8]) -> io::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        // Truncate when starting a fresh sequence at offset 0
        if offset == 0 {
            let mut file = opts.truncate(true).open(path)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(data)?;
            println!("Wrote {} bytes to {}", data.len(), path.display());
            return Ok(());
        }
        let mut file = opts.open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        println!("Wrote {} bytes to {}", data.len(), path.display());
        Ok(())
    }

    // Decide which file path this sector should write to, creating mappings as needed
    fn resolve_or_create_mapping_for_sector(&mut self, sector: u32, lookahead: &[u8]) -> io::Result<Option<PathBuf>> {
        // If we already have a mapping for this sector
        if let Some(path) = self.sector_to_file.get(&sector).cloned() {
            if self.writeable_dirs.contains(&path) {
                // Writing into a directory region: choose/create a file in that directory
                return Ok(Some(self.ensure_active_file_in_dir_for_stream(&path, sector, lookahead)?));
            }

            if self.writeable_paths.contains(&path) {
                return Ok(Some(path));
            }

            // Mapped but read-only
            println!("Write denied: {} is read-only", path.display());
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("Read-only path: {}", path.display())));
        }

        // No mapping: try dynamic file creation in writable directories
        println!("=== NO SECTOR MAPPING FOUND ===\n");
        println!("Sector: {}", sector);
        println!("Checking for writable directories...");
        
        // Check if sector falls within any writable directory range
        let writeable_dirs_clone = self.writeable_dirs.clone();
        for writable_dir in &writeable_dirs_clone {
            println!("Checking writable directory: {}", writable_dir.display());
            // Try to create file dynamically in this directory
            match self.create_file_dynamically(sector, writable_dir, lookahead) {
                Ok(file_path) => {
                    println!("Successfully created file dynamically: {}", file_path.display());
                    return Ok(Some(file_path));
                }
                Err(e) => {
                    println!("Failed to create file in {}: {}", writable_dir.display(), e);
                    continue;
                }
            }
        }
        
        println!("No writable directories available for dynamic file creation");
        // Fallback to original cache routing
        self.route_high_sector_to_cache(sector, lookahead)
    }

    fn ensure_active_file_in_dir_for_stream(&mut self, dir: &Path, sector: u32, lookahead: &[u8]) -> io::Result<PathBuf> {
        // Reuse an active file if present
        if let Some((start_sector, path)) = &self.active_cache_file {
            // If we're still writing sequentially, keep using it
            if sector >= *start_sector {
                return Ok(path.clone());
            }
        }

        // Choose target directory and filename based on content
        // If content looks like HDDL cache, prefer CFG directory if available
        let preferred_dir: PathBuf = if lookahead.len() >= 4 && &lookahead[0..4] == b"NIDC" {
            // Prefer NHDDL directory for title cache (nhddl/cache.bin)
            if let Some(nhddl_dir) = self
                .writeable_dirs
                .iter()
                .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("NHDDL"))
                .cloned()
            {
                nhddl_dir
            } else if let Some(cfg_dir) = self
                .writeable_dirs
                .iter()
                .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("CFG"))
                .cloned()
            {
                cfg_dir
            } else if let Some(cache_dir) = self
                .writeable_dirs
                .iter()
                .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("CACHE"))
                .cloned()
            {
                cache_dir
            } else {
                dir.to_path_buf()
            }
        } else {
            dir.to_path_buf()
        };

        println!("=== FILE CREATION FOR SECTOR {} ===", sector);
        println!("Attempting dynamic file creation in directory: {}", preferred_dir.display());
        
        // Create file dynamically based on content
        let file_path = self.create_file_dynamically(sector, &preferred_dir, lookahead)?;
        println!("Using dynamically created file: {}", file_path.display());
        println!("=== END FILE CREATION DEBUG ===");

        // file_path is already created above by create_file_dynamically

        // Record mappings for subsequent sectors
        self.active_cache_file = Some((sector, file_path.clone()));
        self.writeable_paths.insert(file_path.clone());
        self.file_to_start_sector.insert(file_path.clone(), sector);
    // Ensure the very first write to this file starts at offset 0
    self.file_write_offsets.insert(file_path.clone(), 0);

        // Map a generous range for this new file
        for i in 0..10000u32 {
            self.sector_to_file.insert(sector + i, file_path.clone());
        }

        Ok(file_path)
    }

    fn route_high_sector_to_cache(&mut self, sector: u32, lookahead: &[u8]) -> io::Result<Option<PathBuf>> {
        // Pick a target directory (prefer CFG for cache.bin as per HDDL)
        let maybe_cache = self
            .writeable_dirs
            .iter()
            // Prefer NHDDL for NHDDL client cache
            .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("NHDDL"))
            .cloned()
            .or_else(|| self.writeable_dirs
                .iter()
                .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("CFG"))
                .cloned())
            .or_else(|| self.writeable_dirs
                .iter()
                .find(|p| p.to_string_lossy().to_ascii_uppercase().contains("CACHE"))
                .cloned())
            .or_else(|| self.writeable_dirs.iter().next().cloned());

        if let Some(target_dir) = maybe_cache {
            let file_path = self.ensure_active_file_in_dir_for_stream(&target_dir, sector, lookahead)?;
            // Also ensure mapping entry for this exact sector exists
            self.sector_to_file.insert(sector, file_path.clone());
            return Ok(Some(file_path));
        }

        // No writable dirs available
        Ok(None)
    }

    fn add_new_file_to_virtual_filesystem(&mut self, file_path: &Path) -> io::Result<()> {
        // Find the directory cluster for the parent directory
        let parent_dir = file_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "File has no parent directory")
        })?;
        
        println!("Looking up directory cluster for parent: {}", parent_dir.display());
        
        // Look up the directory cluster from our mapping
        let parent_cluster = self.dir_to_cluster.get(parent_dir).cloned();
        
        println!("Available directory mappings:");
        for (path, cluster) in &self.dir_to_cluster {
            println!("  {} -> cluster {}", path.display(), cluster);
        }

        if let Some(dir_cluster) = parent_cluster {
            println!("Found directory cluster {} for {}", dir_cluster, parent_dir.display());
            let file_name = file_path.file_name()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid file name"))?
                .to_string_lossy();
            
            println!("Adding {} to virtual filesystem in directory cluster {}", file_name, dir_cluster);
            
            // Add the file to the virtual filesystem
            match self.vexfat.map_file(dir_cluster, file_path) {
                Ok(file_cluster) => {
                    println!("Successfully added {} to virtual filesystem (cluster {})", file_path.display(), file_cluster);
                    
                    // Update sector mappings for the newly added file
                    let sectors_per_cluster = self.vexfat.sectors_per_cluster();
                    let start_sector = self.vexfat.cluster_heap_offset() + 
                        (file_cluster.saturating_sub(2) * sectors_per_cluster);
                    
                    // Map sectors for this new file  
                    for i in 0..100 {
                        self.sector_to_file.insert(start_sector + i, file_path.to_path_buf());
                    }
                    println!("Mapped virtual filesystem sectors {}-{} to {}", 
                        start_sector, start_sector + 99, file_path.display());
                    
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Failed to add {} to virtual filesystem: {:?}", file_path.display(), e);
                    Err(io::Error::new(io::ErrorKind::Other, format!("vexfat mapping failed: {:?}", e)))
                }
            }
        } else {
            println!("Parent directory not found in directory mappings for {}", file_path.display());
            println!("This means the virtual filesystem directory structure wasn't updated.");
            Ok(()) // Don't fail the write operation, just skip virtual filesystem integration
        }
    }

    pub fn flush_writes(&mut self) -> io::Result<()> {
        // Integrate any newly created files into the virtual filesystem so the client can see them
        if self.newly_created_files.is_empty() {
            return Ok(());
        }

        println!("Finalizing {} new file(s) into virtual filesystem", self.newly_created_files.len());

        let files = std::mem::take(&mut self.newly_created_files);
        for new_file in files {
            if let Err(err) = self.add_new_file_to_virtual_filesystem(&new_file) {
                eprintln!("Warning: Failed to add {} to virtual filesystem: {}", new_file.display(), err);
            }
        }

        Ok(())
    }

    pub fn atomic_write(&mut self, sectors: &[(u32, Vec<u8>)]) -> Result<(), WriteError> {
        // Validate all writes first
        for (sector, _) in sectors {
            if let Some(file_path) = self.sector_to_file.get(sector) {
                if !self.writeable_paths.contains(file_path) {
                    return Err(WriteError::ReadOnlyFile(file_path.clone()));
                }
            }
        }
        
        // Apply all writes
        for (sector, data) in sectors {
            self.write_cache.insert(*sector, data.clone());
            self.dirty_sectors.insert(*sector);
        }
        
        self.flush_writes()?;
        Ok(())
    }

    pub fn get_write_stats(&self) -> (usize, usize, usize) {
        (
            self.write_cache.len(),
            self.dirty_sectors.len(), 
            self.writeable_paths.len()
        )
    }

}
