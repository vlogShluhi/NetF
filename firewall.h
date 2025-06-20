#ifndef FIREWALL_H
#define FIREWALL_H

#include <cstdint>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <ctime>
#include <map>
#include <set>
#include <mutex>
#include <iomanip>
class firewall
{
public:
    firewall();
    static void showAtackPool(){
        for(auto& ip :  firewall::SYNatack_ip_pool){
            // std::cout<<std::endl<<ip<<std::endl;
        }
    }
    static void analyzePacket(const u_char* packet, const struct pcap_pkthdr* header) {
        static std::map<uint32_t,int> UDP_count_map;
        static std::map<uint32_t,int> ICMP_count_map;
        static std::map<uint32_t,int> SYN_count_map;
        static std::map<uint32_t,int> FIN_count_map;
        static std::map<uint32_t,int> Null_Scan_count_map;
        static std::map<uint32_t,int> Xmas_Scan_count_map;
        // std::cout << "\nPacket size: " << header->len << " bytes"
        //           << " | Captured: " << header->caplen << " bytes"
        //           << " | Timestamp: " << header->ts.tv_sec << "."
        //           << std::setfill('0') << std::setw(6) << header->ts.tv_usec
        //           << std::endl;

        if (header->caplen < sizeof(struct ether_header)) {
            std::cout << "Truncated packet (too small for Ethernet header)" << std::endl;
            return;
        }

        struct ether_header* eth = (struct ether_header*)packet;
        // std::cout << "Ethernet: "
        //           << "Dest: " << std::hex << std::setfill('0')
        //           << std::setw(2) << (int)eth->ether_dhost[0] << ":"
        //           << std::setw(2) << (int)eth->ether_dhost[1] << ":"
        //           << std::setw(2) << (int)eth->ether_dhost[2] << ":"
        //           << std::setw(2) << (int)eth->ether_dhost[3] << ":"
        //           << std::setw(2) << (int)eth->ether_dhost[4] << ":"
        //           << std::setw(2) << (int)eth->ether_dhost[5] << "  "
        //           << "Source: "
        //           << std::setw(2) << (int)eth->ether_shost[0] << ":"
        //           << std::setw(2) << (int)eth->ether_shost[1] << ":"
        //           << std::setw(2) << (int)eth->ether_shost[2] << ":"
        //           << std::setw(2) << (int)eth->ether_shost[3] << ":"
        //           << std::setw(2) << (int)eth->ether_shost[4] << ":"
        //           << std::setw(2) << (int)eth->ether_shost[5] << "  "
        //           << "Type: 0x" << std::setw(4) << ntohs(eth->ether_type)
        //           << std::dec << std::endl;

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
                // std::cout << "Truncated IP packet" << std::endl;
                return;
            }

            struct ip* iph = (struct ip*)(packet + sizeof(struct ether_header));
            uint32_t src_ip = iph->ip_src.s_addr;//Атакующий IP

            // std::cout << "IP: "
            //           << "Version: " << iph->ip_v
            //           << " Header len: " << (iph->ip_hl * 4) << " bytes"
            //           << " TTL: " << (int)iph->ip_ttl
            //           << " Protocol: " << (int)iph->ip_p
            //           << " Source: " << inet_ntoa(iph->ip_src)
            //           << " Dest: " << inet_ntoa(iph->ip_dst)
            //           << std::endl;
            if(iph->ip_p == IPPROTO_UDP) {//UDP flood
                checkFloodAttack(src_ip,UDP_count_map,1,"UDP flood");
            }
            if(iph->ip_p == IPPROTO_ICMP) {//ICMP flood 
                checkFloodAttack(src_ip,ICMP_count_map,1,"ICMP flood ");
            }
            if(iph->ip_p == 6){
                int ip_header_len = iph->ip_hl * 4;
                if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
                    // std::cout << "Truncated TCP packet" << std::endl;
                    return;
                }
                struct tcphdr* tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
                // if (tcph->th_flags & TH_FIN) std::cout << "FIN ";
                // if (tcph->th_flags & TH_SYN) std::cout << "SYN ";
                // if (tcph->th_flags & TH_RST) std::cout << "RST ";
                // if (tcph->th_flags & TH_PUSH) std::cout << "PSH ";
                // if (tcph->th_flags & TH_ACK) std::cout << "ACK ";
                // if (tcph->th_flags & TH_URG) std::cout << "URG ";
                // std::cout << std::endl;
                uint8_t flags = tcph->th_flags;
                if((flags & TH_SYN) && !(flags & TH_ACK)){//SYN flood
                    checkFloodAttack(src_ip,SYN_count_map,20,"SYN flood");
                }
                if((flags & TH_FIN) && (flags & TH_URG) && (flags & TH_PUSH) &&!(flags & TH_SYN) && !(flags & TH_ACK)) {//Xmas scan
                checkFloodAttack(src_ip, Xmas_Scan_count_map, 10, "Xmas Scan");
            }
                if((flags & TH_FIN) && !(flags & TH_SYN)){// FIN scan
                    checkFloodAttack(src_ip,FIN_count_map,20,"FIN flood");
                }
                if ((flags & (TH_SYN | TH_ACK | TH_FIN | TH_RST)) == 0) {//Null scan
                    checkFloodAttack(src_ip, Null_Scan_count_map, 20, "Null Scan");
                }
                            
            }
        }
    }

private:
   static void checkFloodAttack(uint32_t src_ip,
                            std::map<uint32_t, int>& count_map,
                            int threshold,
                            const std::string& attack_name) {
    count_map[src_ip]++;
    time_t now = time(nullptr);
    if (now - last_reset_time >= 1) { 
        for (auto& [ip, count] : count_map) {
            if (count > threshold) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
                std::cout << "[ALERT] Possible " << attack_name << " from: "
                          << ip_str << " (" << count << " packets)" << std::endl;
                SYNatack_ip_pool.insert(ip);
                showAtackPool();
            }
        }
        count_map.clear();
        last_reset_time = now;
    }
}

    static inline time_t last_reset_time = time(nullptr);
    static inline std::set<uint32_t> SYNatack_ip_pool = {};
};

#endif // FIREWALL_H
