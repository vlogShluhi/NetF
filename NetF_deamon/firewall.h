#ifndef FIREWALL_H
#define FIREWALL_H

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
#include <vector>

class firewall {
public:
  struct AttackInfo {
    std::string type;
    std::string source_ip;
    int count;
    time_t timestamp;
  };

  firewall();
  static void analyzePacket(const u_char *packet,
                            const struct pcap_pkthdr *header);

  static std::vector<AttackInfo> getDetectedAttacks();
  static void clearDetectedAttacks();

private:
  static void cleanupOldEntries(std::map<uint32_t, int> &attempts,
                                std::map<uint32_t, time_t> &timestamps,
                                time_t timeout);
  static void checkFloodAttack(uint32_t src_ip,
                               std::map<uint32_t, int> &count_map,
                               int threshold, const std::string &attack_name);

  static std::vector<AttackInfo> detected_attacks;
  static std::mutex attacks_mutex;
  static time_t last_reset_time;
  static std::set<uint32_t> SYNatack_ip_pool;
};

#endif // FIREWALL_H