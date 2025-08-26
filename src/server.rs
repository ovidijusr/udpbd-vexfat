use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
};

use anyhow::Context;
use arbitrary_int::{u4, u9};

use crate::{
    protocol::{
        BlockType, Command, Header, InfoReply, InfoRequest, Rdma, ReadWriteRequest, WriteReply,
        RDMA_MAX_PAYLOAD, UDPBD_PORT, UDP_MAX_PAYLOAD,
    },
    vexfat::VexFat,
    Args,
};

pub struct Server {
    block_device: VexFat,
    socket: UdpSocket,
    write_size_left: usize,
    write_rdma_valid: bool,
}

impl Server {
    pub fn new(args: &Args) -> anyhow::Result<Self> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), UDPBD_PORT);
        let socket = UdpSocket::bind(addr).context("Failed to create UDP socket")?;
        socket
            .set_broadcast(true)
            .context("Failed to enable broadcast on UDP socket")?;

        let vexfat = VexFat::new(args);

        let mut server = Server {
            block_device: vexfat,
            socket,
            write_size_left: 0,
            write_rdma_valid: false,
        };
        server.block_device.set_block_shift(5); // 128b blocks

        Ok(server)
    }

    pub fn run(&mut self) {
        let mut buf = [0u8; UDP_MAX_PAYLOAD];
        println!("Server running on port {}", UDPBD_PORT);

        loop {
            let (_, addr) = self.socket.recv_from(&mut buf[..]).unwrap();

            macro_rules! cast_buffer_as {
                ($type:ty) => {
                    bytemuck::from_bytes::<$type>(&buf[..size_of::<$type>()])
                };
            }

            let header = cast_buffer_as!(Header);
            match header.command() {
                Ok(cmd) => match cmd {
                    Command::Info => self.handle_cmd_info(cast_buffer_as!(InfoRequest), addr),
                    Command::Read => self.handle_cmd_read(cast_buffer_as!(ReadWriteRequest), addr),
                    Command::Write => self.handle_cmd_write(cast_buffer_as!(ReadWriteRequest)),
                    Command::WriteRdma => self.handle_cmd_write_rdma(cast_buffer_as!(Rdma), addr),
                    cmd => println!("Unexpected command: {cmd:?}"),
                },
                Err(cmd) => println!("Unknown command: {cmd}"),
            };
        }
    }

    fn handle_cmd_info(&mut self, req: &InfoRequest, addr: SocketAddr) {
        println!("UDPBD_CMD_INFO from {addr}");

        let reply = InfoReply {
            header: Header::new_with_raw_value(0)
                .with_command(Command::InfoReply)
                .with_command_id(req.header.command_id())
                .with_command_pkt(1),
            sector_size: u32::from(self.block_device.sector_size()),
            sector_count: self.block_device.sector_count(),
        };
        let ser = bytemuck::bytes_of(&reply);

        if let Err(err) = self.socket.send_to(ser, addr) {
            eprintln!("Failed to reply with UDPBD_CMD_INFO_REPLY to {addr}: {err}");
        }
    }

    fn handle_cmd_read(&mut self, req: &ReadWriteRequest, addr: SocketAddr) {
        let ReadWriteRequest {
            sector_nr,
            sector_count,
            ..
        } = *req;

        println!(
            "UDPBD_CMD_READ(cmdId={}, startSector={}, sectorCount={})",
            req.header.command_id(),
            sector_nr,
            sector_count
        );

        self.block_device.set_block_shift_sectors(sector_count);

        let mut reply = Rdma {
            header: Header::new_with_raw_value(0)
                .with_command(Command::ReadRdma)
                .with_command_id(req.header.command_id())
                .with_command_pkt(1),
            block_type: BlockType::new_with_raw_value(0)
                .with_block_shift(u4::new(self.block_device.block_shift)),
            data: [0; RDMA_MAX_PAYLOAD],
        };

        let mut seeked = true;
        if let Err(err) = self.block_device.seek(sector_nr) {
            eprintln!("Failed to seek block device in UDPBD_CMD_READ for {addr}: {err}");
            seeked = false;
        }

        let mut blocks_left = sector_count * self.block_device.blocks_per_socket;
        while blocks_left > 0 {
            let block_count = if blocks_left > self.block_device.blocks_per_packet {
                self.block_device.blocks_per_packet
            } else {
                blocks_left
            };
            reply.block_type = reply.block_type.with_block_count(u9::new(block_count));
            blocks_left -= block_count;

            // read data from file
            let size = usize::from(block_count * self.block_device.block_size);
            let buf = &mut reply.data[..size];
            if seeked {
                if let Err(err) = self.block_device.read(buf) {
                    eprintln!(
                        "Failed to read block device in UDPBD_CMD_READ for {addr}, zeroing: {err}"
                    );
                    reply.data = [0; RDMA_MAX_PAYLOAD];
                }
            }

            let ser = bytemuck::bytes_of(&reply);
            let resp = &ser[..size_of::<Header>() + size_of::<BlockType>() + size];

            // send packet to PS2
            if let Err(err) = self.socket.send_to(resp, addr) {
                eprintln!("Failed to reply with UDPBD_CMD_READ_RDMA to {addr}: {err}");
            }

            let next_cmd_pkt = reply.header.command_pkt() + 1;
            reply.header = reply.header.with_command_pkt(next_cmd_pkt);
        }
    }

    fn handle_cmd_write(&mut self, req: &ReadWriteRequest) {
        let ReadWriteRequest {
            sector_nr,
            sector_count,
            ..
        } = *req;
        println!(
            "UDPBD_CMD_WRITE(cmdId={}, startSector={}, sectorCount={})",
            req.header.command_id(),
            sector_nr,
            sector_count
        );

        // Reset per-request write tracking
        self.write_size_left =
            usize::from(sector_count) * usize::from(self.block_device.sector_size());

    // Reset per-write sequence state so file offsets start at 0 for new files
    self.block_device.begin_write_sequence();

    match self.block_device.seek(sector_nr) {
            Ok(_) => {
                self.write_rdma_valid = true;
                // Also reset intra-sector offset so RDMA writes start cleanly for this request
                // The VexFat layer maintains per-file sequential offsets for the target path.
            }
            Err(err) => {
                eprintln!("Failed to seek to sector {sector_nr}: {err}");
                self.write_rdma_valid = false;
            }
        }
    }

    fn handle_cmd_write_rdma(&mut self, req: &Rdma, addr: SocketAddr) {
        let size = req.block_type.blocks_size();
        let data = &req.data[..size];

        println!("WRITE_RDMA: {} bytes from {}", size, addr);

        // Only process RDMA if a write request has primed the state
        if !self.write_rdma_valid {
            println!("Write RDMA not valid, ignoring packet (no active write)");
            return;
        }

        if let Err(err) = self.block_device.write(data) {
            eprintln!("Failed to write data to block device: {}", err);
        } else {
            println!("Successfully wrote {} bytes", size);
        }

        // Track remaining bytes for this write sequence
        self.write_size_left = self
            .write_size_left
            .saturating_sub(size);

        if self.write_size_left == 0 && self.write_rdma_valid {
            // Complete this write request quickly to avoid client timeout
            let reply = WriteReply {
                header: Header::new_with_raw_value(0)
                    .with_command(Command::WriteDone)
                    .with_command_id(req.header.command_id())
            .with_command_pkt(1),
                result: 0,
            };
            let ser = bytemuck::bytes_of(&reply);

            if let Err(err) = self.socket.send_to(ser, addr) {
                eprintln!("Failed to reply with UDPBD_CMD_WRITE_DONE to {addr}: {err}");
            };

            // Finalize new files into the virtual filesystem so reads see them
            if let Err(err) = self.block_device.flush_writes() {
                eprintln!("Warning: flush_writes failed: {}", err);
            }

            // Reset write sequence state
            self.write_rdma_valid = false;
            self.write_size_left = 0;
        }
    }
}
