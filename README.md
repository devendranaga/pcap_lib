# PCAP library

PCAP_lib is a lightweight reader and writer library for reading and writing pcaps.

This simply uses the pcap's global and packet header to read from and write to the pcaps and compatible with general `.pcap` format files (not with `.pcapng`).

This is useful when writing custom software for network monitoring, logging and analysis and not want to use `libpcap` (there is no reason **NOT** to use libpcap anyway).

