pub mod pcap;


#[cfg(test)]
mod tests {
    use super::*;

    fn read_pcap() {
        let mut pcap_rd = pcap::PcapReader::new("./test.pcap");

        let mut rx_pkt : [u8; 20] = [0; 20];
        let mut pcap_hdr = pcap::PcapHeader::new();

        pcap_rd.read(&mut rx_pkt, &mut pcap_hdr);

        for i in 0..20 {
            println!("byte [{}]: {:#02?}", i, rx_pkt[i]);
        }
    }

    #[test]
    fn write_pcap() {
        let mut pcap_wr = pcap::PcapWriter::new("./test.pcap");

        let mut eth_pkt : [u8; 20] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x00, 0x01, 0x02, 0x04, 0x05, 0x06,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
        ];

        pcap_wr.write(&mut eth_pkt, 20);
        read_pcap();
    }
}
