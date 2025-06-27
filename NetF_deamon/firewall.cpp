
#include "firewall.h"
#include "vector"
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <set>
#include <sys/types.h>

std::vector<firewall::AttackInfo> firewall::detected_attacks;
std::mutex firewall::attacks_mutex;
time_t firewall::last_reset_time;
std::set<uint32_t> firewall::SYNatack_ip_pool;

firewall::firewall() { last_reset_time = time(nullptr); }

std::vector<firewall::AttackInfo> firewall::getDetectedAttacks() {
  std::lock_guard<std::mutex> lock(attacks_mutex);
  return detected_attacks;
}

void firewall::clearDetectedAttacks() {
  std::lock_guard<std::mutex> lock(attacks_mutex);
  detected_attacks.clear();
}

void firewall::cleanupOldEntries(std::map<uint32_t, int> &attempts,
                                 std::map<uint32_t, time_t> &timestamps,
                                 time_t timeout) {
  time_t now = time(nullptr);
  for (auto it = timestamps.begin(); it != timestamps.end();) {
    if (now - it->second > timeout) {
      attempts.erase(it->first);
      it = timestamps.erase(it);
    } else {
      ++it;
    }
  }
}

void firewall::checkFloodAttack(uint32_t src_ip,
                                std::map<uint32_t, int> &count_map,
                                int threshold, const std::string &attack_name) {
  count_map[src_ip]++;
  time_t now = time(nullptr);

  if (now - last_reset_time >= 1) {
    for (auto &[ip, count] : count_map) {
      if (count > threshold) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);

        std::lock_guard<std::mutex> lock(attacks_mutex);
        detected_attacks.push_back({attack_name, ip_str, count, now});

        SYNatack_ip_pool.insert(ip);
      }
    }
    count_map.clear();
    last_reset_time = now;
  }
}

void firewall::analyzePacket(const u_char *packet,
                             const struct pcap_pkthdr *header) {
  static std::map<uint32_t, int> UDP_count_map;
  static std::map<uint32_t, int> ICMP_count_map;
  static std::map<uint32_t, int> SYN_count_map;
  static std::map<uint32_t, int> FIN_count_map;
  static std::map<uint32_t, int> Null_Scan_count_map;
  static std::map<uint32_t, int> Xmas_Scan_count_map;
  static std::map<uint32_t, std::set<uint16_t>> scanned_ports;
  static std::map<uint32_t, time_t> scaned_ports_timestamps;

  std::cout << "\nPacket size: " << header->len << " bytes"
            << " | Captured: " << header->caplen << " bytes"
            << " | Timestamp: " << header->ts.tv_sec << "." << std::setfill('0')
            << std::setw(6) << header->ts.tv_usec << std::endl;

  if (header->caplen < sizeof(struct ether_header)) {
    std::cout << "Truncated packet (too small for Ethernet header)"
              << std::endl;
    return;
  }

  struct ether_header *eth = (struct ether_header *)packet;
  std::cout << "Ethernet: "
            << "Dest: " << std::hex << std::setfill('0') << std::setw(2)
            << (int)eth->ether_dhost[0] << ":" << std::setw(2)
            << (int)eth->ether_dhost[1] << ":" << std::setw(2)
            << (int)eth->ether_dhost[2] << ":" << std::setw(2)
            << (int)eth->ether_dhost[3] << ":" << std::setw(2)
            << (int)eth->ether_dhost[4] << ":" << std::setw(2)
            << (int)eth->ether_dhost[5] << "  "
            << "Source: " << std::setw(2) << (int)eth->ether_shost[0] << ":"
            << std::setw(2) << (int)eth->ether_shost[1] << ":" << std::setw(2)
            << (int)eth->ether_shost[2] << ":" << std::setw(2)
            << (int)eth->ether_shost[3] << ":" << std::setw(2)
            << (int)eth->ether_shost[4] << ":" << std::setw(2)
            << (int)eth->ether_shost[5] << "  "
            << "Type: 0x" << std::setw(4) << ntohs(eth->ether_type) << std::dec
            << std::endl;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) {
      std::cout << "Truncated IP packet" << std::endl;
      return;
    }

    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    uint32_t src_ip = iph->ip_src.s_addr;

    std::cout << "IP: "
              << "Version: " << iph->ip_v << " Header len: " << (iph->ip_hl * 4)
              << " bytes"
              << " TTL: " << (int)iph->ip_ttl << " Protocol: " << (int)iph->ip_p
              << " Source: " << inet_ntoa(iph->ip_src)
              << " Dest: " << inet_ntoa(iph->ip_dst) << std::endl;

    if (iph->ip_p == IPPROTO_UDP) {
      checkFloodAttack(src_ip, UDP_count_map, 1, "UDP flood");
    }
    if (iph->ip_p == IPPROTO_ICMP) {
      checkFloodAttack(src_ip, ICMP_count_map, 1, "ICMP flood");
    }
    if (iph->ip_p == 6) {
      int ip_header_len = iph->ip_hl * 4;
      if (header->caplen <
          sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
        std::cout << "Truncated TCP packet" << std::endl;
        return;
      }

      struct tcphdr *tcph =
          (struct tcphdr *)(packet + sizeof(struct ether_header) +
                            ip_header_len);
      uint8_t flags = tcph->th_flags;

      scanned_ports[src_ip].insert(ntohs(tcph->th_dport));
      scaned_ports_timestamps[src_ip] = time(nullptr);

      if (scanned_ports[src_ip].size() > 15) {
        time_t now = time(nullptr);
        if (now - scaned_ports_timestamps[src_ip] < 60) {
          std::cout << "[ALERT] Port Scan detected from: "
                    << inet_ntoa(iph->ip_src) << " ("
                    << scanned_ports[src_ip].size() << " ports in "
                    << (now - scaned_ports_timestamps[src_ip]) << " seconds)"
                    << std::endl;
          SYNatack_ip_pool.insert(src_ip);
          scanned_ports.erase(src_ip);
          scaned_ports_timestamps.erase(src_ip);
        }
      }

      if (ntohs(tcph->th_dport) == 22) {
        static std::map<uint32_t, int> ssh_connect_attempts;
        static std::map<uint32_t, int> ssh_bruteforce_attempts;
        static std::map<uint32_t, time_t> last_ssh_connect;
        static std::map<uint32_t, time_t> last_ssh_bruteforce;
        time_t now = time(nullptr);
        last_ssh_connect[src_ip] = now;

        if (tcph->th_flags == TH_SYN) {
          if (now - last_ssh_connect[src_ip] > 60) {
            ssh_connect_attempts[src_ip] = 0;
          }

          ssh_connect_attempts[src_ip]++;
          last_ssh_connect[src_ip] = now;

          if (ssh_connect_attempts[src_ip] > 5) {
            std::cout << "[ALERT] Possible SSH connection flood from: "
                      << inet_ntoa(iph->ip_src) << " ("
                      << ssh_connect_attempts[src_ip] << " SYNs in 60s)"
                      << std::endl;
            SYNatack_ip_pool.insert(src_ip);
          }
        }

        if ((tcph->th_flags & (TH_SYN | TH_FIN | TH_RST)) == 0) {
          if (now - last_ssh_connect[src_ip] > 60) {
            ssh_bruteforce_attempts[src_ip] = 0;
          }

          ssh_bruteforce_attempts[src_ip]++;
          last_ssh_bruteforce[src_ip] = now;

          if (ssh_bruteforce_attempts[src_ip] > 10) {
            std::cout << "[ALERT] Possible SSH bruteforce from: "
                      << inet_ntoa(iph->ip_src) << " ("
                      << ssh_bruteforce_attempts[src_ip]
                      << " auth attempts in 60s)" << std::endl;
            SYNatack_ip_pool.insert(src_ip);
          }
        }

        static time_t last_cleanup = 0;
        if (now - last_cleanup > 300) {
          cleanupOldEntries(ssh_connect_attempts, last_ssh_connect, 300);
          cleanupOldEntries(ssh_bruteforce_attempts, last_ssh_bruteforce, 300);
          last_cleanup = now;
        }
      }

      if ((flags & TH_SYN) && !(flags & TH_ACK)) {
        checkFloodAttack(src_ip, SYN_count_map, 20, "SYN flood");
      }

      if ((flags & TH_FIN) && (flags & TH_URG) && (flags & TH_PUSH) &&
          !(flags & TH_SYN) && !(flags & TH_ACK)) {
        checkFloodAttack(src_ip, Xmas_Scan_count_map, 10, "Xmas Scan");
      }

      if ((flags & TH_FIN) && !(flags & TH_SYN)) {
        checkFloodAttack(src_ip, FIN_count_map, 20, "FIN flood");
      }

      if ((flags & (TH_SYN | TH_ACK | TH_FIN | TH_RST)) == 0) {
        checkFloodAttack(src_ip, Null_Scan_count_map, 20, "Null Scan");
      }
    }
  }
}