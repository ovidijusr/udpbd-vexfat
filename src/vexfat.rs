use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write}, 
    path::{Path, PathBuf, MAIN_SEPARATOR_STR},
};

use vexfatbd::VirtualExFatBlockDevice;
use walkdir::WalkDir;

use crate::{
    protocol::RDMA_MAX_PAYLOAD,
    utils::{relative_path_from_common_root, unsigned_align_to, unsigned_rounded_up_div},
    Args,
};

const BYTES_PER_SECTOR_SHIFT: u8 = 9; // 512 bytes

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
    writeable_paths: HashSet<PathBuf>,
    dirty_sectors: HashSet<u32>,
    current_write_sector: u32,
}

impl VexFat {
    fn is_writeable_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        path_str.contains("art") || path_str.contains("cfg") || 
        path_str.contains("cache") || path_str.contains("save") ||
        path_str.contains("tmp") || path_str.contains("temp")
    }

    pub fn new(args: &Args) -> Self {
        let root: std::path::PathBuf = args.root.clone();
        let prefix = match &args.prefix {
            Some(name) => name.clone(),
            None => String::new(),
        };

        for name in [
            "APPS", "ART", "CD", "CFG", "DVD", "CHT", "LNG", "THM", "VMC",
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
        let metadata_clusters = (5 * (total_dirs_count + total_files_count) as u64); // Increased from 3 to 5
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

        let mut dirpath_to_cluster = HashMap::from([(root.clone(), prefix_cluster)]);
        let sector_to_file = HashMap::new();
        let mut writeable_paths = HashSet::new();

        for (path, is_file) in items {
            let parent = path.parent().unwrap().to_owned();
            let parent_cluster = dirpath_to_cluster.get(&parent).cloned().unwrap();

            if is_file {
                if let Err(err) = vexfat.map_file(parent_cluster, &path) {
                    println!("! Failed to map file {}: {:?}", path.display(), err);
                }
            } else {
                let name: &str = path.file_name().unwrap().to_str().unwrap();

                match vexfat.add_directory(parent_cluster, name) {
                    Ok(dir_cluster) => {
                        dirpath_to_cluster.insert(path.to_owned(), dir_cluster);
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

        Self {
            vexfat,
            sector_count: sector_count as u32,
            block_shift: 0,
            block_size: 0,
            blocks_per_packet: 0,
            blocks_per_socket: 0,
            
            write_cache: HashMap::new(),
            sector_to_file,
            writeable_paths,
            dirty_sectors: HashSet::new(),
            current_write_sector: 0,
        }
    }

    pub fn seek(&mut self, sector: u32) -> io::Result<()> {
        let offset = u64::from(sector) * u64::from(self.sector_size());
        self.current_write_sector = sector;

        self.vexfat
            .seek(std::io::SeekFrom::Start(offset))
            .map(|_| ())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.vexfat.read_exact(buf).map(|_| ())
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        let current_sector = self.current_write_sector;
        
        // Check if this sector belongs to a writeable file
        if let Some(file_path) = self.sector_to_file.get(&current_sector) {
            if self.writeable_paths.contains(file_path) {
                // Cache the write for later flush
                self.write_cache.insert(current_sector, buf.to_vec());
                self.dirty_sectors.insert(current_sector);
                println!("Cached write to sector {} ({})", current_sector, file_path.display());
                self.current_write_sector += 1; // Advance for next write
                return Ok(());
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied, 
                    format!("Read-only file: {}", file_path.display())
                ));
            }
        }
        
        // Handle writes to filesystem metadata (directories, FAT, etc.)
        println!("Metadata write to sector {} ({} bytes)", current_sector, buf.len());
        self.current_write_sector += 1; // Advance for next write
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

    fn calculate_file_offset_for_sector(&self, sector: u32) -> u64 {
        // Calculate the byte offset within the file for a given sector
        // This is a simplified calculation - in reality, we'd need to track
        // the exact mapping from sectors to file offsets
        u64::from(sector % 1000) * u64::from(self.sector_size())
    }

    fn extend_or_create_file(&mut self, path: &Path, sector: u32, data: &[u8]) -> io::Result<()> {
        let real_file_offset = self.calculate_file_offset_for_sector(sector);
        
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let mut file = OpenOptions::new()
            .create(true)
            .write(true) 
            .open(path)?;
            
        file.seek(SeekFrom::Start(real_file_offset))?;
        file.write_all(data)?;
        file.flush()?;
        
        println!("Wrote {} bytes to {}", data.len(), path.display());
        Ok(())
    }

    pub fn flush_writes(&mut self) -> io::Result<()> {
        let dirty_count = self.dirty_sectors.len();
        if dirty_count == 0 {
            return Ok(());
        }

        println!("Flushing {} cached writes to disk", dirty_count);

        let dirty_sectors: Vec<u32> = self.dirty_sectors.iter().cloned().collect();
        
        for sector in dirty_sectors {
            if let (Some(data), Some(file_path)) = (
                self.write_cache.get(&sector).cloned(),
                self.sector_to_file.get(&sector).cloned()
            ) {
                if let Err(err) = self.extend_or_create_file(&file_path, sector, &data) {
                    eprintln!("Failed to flush sector {} to {}: {}", sector, file_path.display(), err);
                }
            }
        }
        
        self.dirty_sectors.clear();
        self.write_cache.clear();
        
        println!("Write cache flushed successfully");
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
