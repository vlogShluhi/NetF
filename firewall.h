#ifndef FIREWALL_H
#define FIREWALL_H

#include <iomanip>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <ctime>
#include <map>
#include <vector>

class firewall
{
public:
    firewall();
    static void showAtackPool(){
        for(auto& ip :  firewall::atack_ip_pool){
            std::cout<<std::endl<<ip<<std::endl;
        }
    }
    static void analyzePacket(const u_char* packet, const struct pcap_pkthdr* header) {
        static std::map<uint32_t,int> syn_count_map;
        static time_t last_reset_time = time(nullptr);
        std::cout << "\nPacket size: " << header->len << " bytes"
                  << " | Captured: " << header->caplen << " bytes"
                  << " | Timestamp: " << header->ts.tv_sec << "."
                  << std::setfill('0') << std::setw(6) << header->ts.tv_usec
                  << std::endl;

        if (header->caplen < sizeof(struct ether_header)) {
            std::cout << "Truncated packet (too small for Ethernet header)" << std::endl;
            return;
        }

        struct ether_header* eth = (struct ether_header*)packet;
        std::cout << "Ethernet: "
                  << "Dest: " << std::hex << std::setfill('0')
                  << std::setw(2) << (int)eth->ether_dhost[0] << ":"
                  << std::setw(2) << (int)eth->ether_dhost[1] << ":"
                  << std::setw(2) << (int)eth->ether_dhost[2] << ":"
                  << std::setw(2) << (int)eth->ether_dhost[3] << ":"
                  << std::setw(2) << (int)eth->ether_dhost[4] << ":"
                  << std::setw(2) << (int)eth->ether_dhost[5] << "  "
                  << "Source: "
                  << std::setw(2) << (int)eth->ether_shost[0] << ":"
                  << std::setw(2) << (int)eth->ether_shost[1] << ":"
                  << std::setw(2) << (int)eth->ether_shost[2] << ":"
                  << std::setw(2) << (int)eth->ether_shost[3] << ":"
                  << std::setw(2) << (int)eth->ether_shost[4] << ":"
                  << std::setw(2) << (int)eth->ether_shost[5] << "  "
                  << "Type: 0x" << std::setw(4) << ntohs(eth->ether_type)
                  << std::dec << std::endl;

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
                std::cout << "Truncated IP packet" << std::endl;
                return;
            }

            struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));
            std::cout << "IP: "
                      << "Version: " << iph->ip_v
                      << " Header len: " << (iph->ip_hl * 4) << " bytes"
                      << " TTL: " << (int)iph->ip_ttl
                      << " Protocol: " << (int)iph->ip_p
                      << " Source: " << inet_ntoa(iph->ip_src)
                      << " Dest: " << inet_ntoa(iph->ip_dst)
                      << std::endl;
            if(iph->ip_p == 6){
                int ip_header_len = iph->ip_hl * 4;
                if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
                    std::cout << "Truncated TCP packet" << std::endl;
                    return;
                }
                struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
                if (tcph->th_flags & TH_FIN) std::cout << "FIN ";
                if (tcph->th_flags & TH_SYN) std::cout << "SYN ";
                if (tcph->th_flags & TH_RST) std::cout << "RST ";
                if (tcph->th_flags & TH_PUSH) std::cout << "PSH ";
                if (tcph->th_flags & TH_ACK) std::cout << "ACK ";
                if (tcph->th_flags & TH_URG) std::cout << "URG ";
                std::cout << std::endl;
                uint8_t flags = tcph->th_flags;
                if((flags&TH_SYN)&!(flags&TH_ACK)){
                    uint32_t src_ip = iph->ip_src.s_addr;//Атакующий IP
                    syn_count_map[src_ip]++;
                    time_t now = time(nullptr);
                    if(now - last_reset_time >=1){
                        for(auto& [ip,count] : syn_count_map){
                            if(count>100){
                                char ip_str[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET,&ip,ip_str,INET_ADDRSTRLEN);
                                std::cout << "[ALERT] Possible SYN flood from: "
                                          << ip_str << " (" << count << " SYNs)" << std::endl;
                                atack_ip_pool.push_back(src_ip);
                                firewall::showAtackPool();
                            }
                        }
                        syn_count_map.clear();
                        last_reset_time = now;
                    }
                }
            }
        }
    }
private:
    static inline std::vector<uint32_t> atack_ip_pool = {};
};

#endif // FIREWALL_H
