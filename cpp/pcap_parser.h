/**
 * @brief - pcap parser library
 *
 * @author - Devendra Naga (devendra.aaru@gmail.com)
 */
#ifndef __PCAP_PARSER_H__
#define __PCAP_PARSER_H__


namespace nc_pcap {

// global header
typedef struct pcap_hdr_s {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} pcap_hdr_t;

// packet header
typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;


// writer interface
class nc_pcap_writer {
    public:
        nc_pcap_writer(std::string filename);
        ~nc_pcap_writer();
        pcaprec_hdr_t format_pcap_pkthdr(size_t pktsize);
        int write_packet(pcaprec_hdr_t *rec, uint8_t *buf);

    private:
        FILE *fp;
        pcap_hdr_t format_default_glob_header();
};

// reader interface
class nc_pcap_reader {
    public:
        nc_pcap_reader(std::string filename);
        ~nc_pcap_reader();
        int read_packet(pcaprec_hdr_t *rec_hdr, uint8_t *buf, size_t buflen);
    private:
        FILE *fp;
        pcap_hdr_t glob_hdr;
        int count = 0;
};

};

#endif

