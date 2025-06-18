#ifndef TRAFFICMONITOR_H
#define TRAFFICMONITOR_H

#include "firewall.h"
#include <pcap.h>
#include <string>

class trafficmonitor
{
public:
    trafficmonitor();

    static void monitorTraffic(const std::string& interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(interface.c_str(), 65536, 1, 5000, errbuf);

        if (!handle) {
            std::cerr << "PCAP error: " << errbuf << std::endl;
            return;
        }

        struct pcap_pkthdr header;
        while(true) {
            const u_char* packet = pcap_next(handle, &header);
            if (!packet) continue;

            firewall::analyzePacket(packet, &header);
        }

        pcap_close(handle);
    }
};

#endif // TRAFFICMONITOR_H
