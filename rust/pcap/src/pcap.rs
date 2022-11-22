/**
 * @brief - Implements Pcap read and write in Rust.
 *
 * @author - Devendra Naga (devendra.aaru@outlook.com).
 *
 * @copyright - 2022-present All rights reserved. Ask for license when copying.
 */
use std::fs::File;
use std::io::{Read, Write};

/**
 * @brief defines a pcap header.
 */
pub struct PcapHeader {
    /* Timestamp in secods */
    pub ts_sec      : u32,

    /* Timestamp in microseconds */
    pub ts_usec     : u32,

    /* Total length */
    pub incl_len    : u32,

    /* Total length */
    pub orig_len    : u32,
}

/**
 * @brief Implements pcap header
 */
impl PcapHeader {
    /**
     * @brief - Return PcapHeader
     */
    pub fn new() -> PcapHeader {
        let pcap_hdr = PcapHeader {
            ts_sec      : 0,
            ts_usec     : 0,
            incl_len    : 0,
            orig_len    : 0,
        };

        pcap_hdr
    }
}

/**
 * @brief - Magic header .. Internal to the lib.
 *
 * Write this magic header for every newly written pcap file
 */
struct PcapMagicHeader {
    magic_number : u32,
    version_major : u16,
    version_minor : u16,
    thiszone : u32,
    sigfigs : u32,
    snaplen : u32,
    network : u32,
}

/**
 * @brief - Defines the PcapWriter.
 */
pub struct PcapWriter {
    f_wr : File,
}

/**
 * @brief - Swap bytes into buffer from 32 bits variable.
 *
 * @param[inout] in_buf : buffer to write.
 * @param[inout] off : buffer offset to write.
 * @param[in] val: val to write.
 */
fn copy_to_buf32(in_buf : &mut [u8], off : &mut usize, val : u32) {
    in_buf[*off] = ((val & 0xFF000000) >> 24) as u8;
    in_buf[*off + 1] = ((val & 0x00FF0000) >> 16) as u8;
    in_buf[*off + 2] = ((val & 0x0000FF00) >> 8) as u8;
    in_buf[*off + 3] = (val & 0x000000FF) as u8;

    *off += 4;
}

/**
 * @brief - Swap bytes into 32 bits variable from buffer.
 *
 * @param[in] in_buf : buffer to write.
 * @param[inout] off : buffer offset to write.
 *
 * @return 32 bits variable with the copied value.
 */
fn copy_from_buf32(in_buf : &mut [u8], off : &mut usize) -> u32 {
    let mut val : u32 = 0;

    val = u32::from(in_buf[*off]) << 24 |
          u32::from(in_buf[*off + 1]) << 16 |
          u32::from(in_buf[*off + 2]) << 8 |
          u32::from(in_buf[*off + 3]);
    *off += 4;
    val
}

/**
 * @brief - Swap bytes into 16 bits variable from buffer.
 *
 * @param[in] in_buf : buffer to write.
 * @param[inout] off : buffer offset to write.
 *
 * @return 32 bits variable with the copied value.
 */
fn copy_from_buf16(in_buf : &mut [u8], off : &mut usize) -> u16 {
    let mut val : u16 = 0;

    val = u16::from(in_buf[*off]) << 8 |
          u16::from(in_buf[*off + 1]);
    *off += 2;
    val
}

/**
 * @brief - Swap bytes into buffer from 16 bits variable.
 *
 * @param[inout] in_buf : buffer to write.
 * @param[inout] off : buffer offset to write.
 * @param[in] val: val to write.
 */
fn copy_to_buf16(in_buf : &mut [u8], off : &mut usize, val: u16) {
    in_buf[*off] = ((val & 0xFF00) >> 8) as u8;
    in_buf[*off + 1] = (val & 0x00FF) as u8;

    *off += 2;
}

/**
 * @brief - Implements Pcap Writer.
 */
impl PcapWriter {
    /**
     * @brief - Initialize the PcapWriter variable.
     *
     * @param[in] file : file to write the PCAP.
     *
     * @return PcapWriter implementation.
     */
    pub fn new(file : &str) -> PcapWriter {
        let mut in_buf : [u8; 200] = [0; 200];
        let mut off : usize = 0;

        let mut pcap_wr = PcapWriter {
            f_wr : match File::create(file) {
                Err(why) => panic!("failed to create {} {}", file, why),
                Ok(f) => f,
            },
        };

        let gh = PcapMagicHeader {
            magic_number    : 0xa1b2c3d4,
            version_major   : 2,
            version_minor   : 4,
            thiszone        : 0,
            sigfigs         : 0,
            snaplen         : 65535,
            network         : 1,
        };

        copy_to_buf32(&mut in_buf, &mut off, gh.magic_number);
        copy_to_buf16(&mut in_buf, &mut off, gh.version_major);
        copy_to_buf16(&mut in_buf, &mut off, gh.version_minor);
        copy_to_buf32(&mut in_buf, &mut off, gh.thiszone);
        copy_to_buf32(&mut in_buf, &mut off, gh.sigfigs);
        copy_to_buf32(&mut in_buf, &mut off, gh.snaplen);
        copy_to_buf32(&mut in_buf, &mut off, gh.network);

        match pcap_wr.f_wr.write(&mut in_buf[..off]) {
            Err(why) => panic!("failed to write magic record header {}", why),
            Ok(_) => pcap_wr
        }
    }

    /**
     * @brief - Write the given input packet to the PCAP.
     *
     * @param [in] pkt_buf : Input packet buffer.
     * @param [in] pkt_buf_len : Length of packet buffer.
     */
    pub fn write(&mut self, pkt_buf : &mut [u8], pkt_buf_len : usize) {
        let pcap_hdr = PcapHeader {
            ts_sec     : 0,
            ts_usec    : 0,
            incl_len   : pkt_buf_len as u32,
            orig_len   : pkt_buf_len as u32,
        };
        let mut buf : [u8; 200] = [0; 200];
        let mut off : usize = 0;

        copy_to_buf32(&mut buf, &mut off, pcap_hdr.ts_sec);
        copy_to_buf32(&mut buf, &mut off, pcap_hdr.ts_usec);
        copy_to_buf32(&mut buf, &mut off, pcap_hdr.incl_len);
        copy_to_buf32(&mut buf, &mut off, pcap_hdr.orig_len);

        self.f_wr.write(&mut buf[..off]).unwrap();

        let mut pos = 0;
        while pos < pkt_buf_len {
            let written = self.f_wr.write(&pkt_buf[pos..]).unwrap();
            pos += written;
        }
    }
}

/**
 * @brief - Defines PCAP reader structure.
 */
pub struct PcapReader {
    f_rd : File,
}

/**
 * @brief - Implements PCAP reader structure.
 */
impl PcapReader {
    /**
     * @brief - Create a new PCAP reader
     *
     * @param[in] file : Input PCAP file.
     *
     * @return PcapReader implementation.
     */
    pub fn new(file : &str) -> PcapReader {
        let mut in_buf : [u8; 24] = [0; 24];
        let mut off : usize = 0;

        let mut pcap_rd = PcapReader {
            f_rd : match File::open(file) {
                Err(why) => panic!("failed to open {} {}", file, why),
                Ok(f) => f,
            },
        };

        let mut gh = PcapMagicHeader {
            magic_number    : 0,
            version_major   : 0,
            version_minor   : 0,
            thiszone        : 0,
            sigfigs         : 0,
            snaplen         : 0,
            network         : 0,
        };

        pcap_rd.f_rd.read(&mut in_buf).unwrap();

        gh.magic_number = copy_from_buf32(&mut in_buf, &mut off);
        if gh.magic_number != 0xa1b2c3d4 {
            panic!("Unsupported magic number in pcap! {}", gh.magic_number);
        }

        gh.version_major = copy_from_buf16(&mut in_buf, &mut off);
        if gh.version_major != 2 {
            panic!("Unsupported version_major in pcap! {}", gh.version_major);
        }

        gh.version_minor = copy_from_buf16(&mut in_buf, &mut off);
        if gh.version_minor != 4 {
            panic!("Unsupported version_minor in pcap! {}", gh.version_minor);
        }

        gh.thiszone = copy_from_buf32(&mut in_buf, &mut off);
        if gh.thiszone != 0 {
            panic!("Unsupported thiszone {}", gh.thiszone);
        }

        gh.sigfigs = copy_from_buf32(&mut in_buf, &mut off);
        if gh.sigfigs != 0 {
            panic!("Unsupported sigfigs {}", gh.sigfigs);
        }

        gh.snaplen = copy_from_buf32(&mut in_buf, &mut off);
        if gh.snaplen != 65535 {
            panic!("Unsupported snaplen {}", gh.snaplen);
        }

        gh.network = copy_from_buf32(&mut in_buf, &mut off);
        if gh.network != 1 {
            panic!("Unsupported network {}", gh.network);
        }

        pcap_rd
    }

    /**
     * @brief - Read PCAP packet
     *
     * @param [inout] - PCAP packet buffer.
     * @param [inout] - The packet header (timestamp, length etc)
     */
    pub fn read(&mut self, pkt_buf : &mut [u8], pcap_hdr : &mut PcapHeader) {
        let mut tmp_buf : [u8; 16] = [0; 16];
        let mut i : usize = 0;
        let mut off : usize = 0;

        self.f_rd.read(&mut tmp_buf).unwrap();
        pcap_hdr.ts_sec     = copy_from_buf32(&mut tmp_buf, &mut off);
        pcap_hdr.ts_usec    = copy_from_buf32(&mut tmp_buf, &mut off);
        pcap_hdr.incl_len   = copy_from_buf32(&mut tmp_buf, &mut off);
        pcap_hdr.orig_len   = copy_from_buf32(&mut tmp_buf, &mut off);

        let mut pkt_content : [u8; 2048] = [0; 2048];

        self.f_rd.read(&mut pkt_content[..pcap_hdr.orig_len as usize]);

        while i < pcap_hdr.orig_len as usize {
            pkt_buf[i] = pkt_content[i];
            i += 1;
        }
    }
}


