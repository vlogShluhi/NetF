#include "firewall.h"
#include "trafficmonitor.h"
#include <csignal>
#include <dbus-1.0/dbus/dbus.h>
#include <iostream>
#include <pwd.h>
#include <thread>
#include <unistd.h>

volatile sig_atomic_t stop_flag = 0;
DBusConnection *dbus_conn = nullptr;

void signal_handler(int signum) {
  stop_flag = 1;
  if (dbus_conn) {
    dbus_connection_unref(dbus_conn);
    dbus_conn = nullptr;
  }
}

bool init_dbus_connection() {
  DBusError err;
  dbus_error_init(&err);

  dbus_conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
  if (dbus_error_is_set(&err)) {
    std::cerr << "D-Bus connection error: " << err.message << std::endl;
    dbus_error_free(&err);
    return false;
  }

  int ret = dbus_bus_request_name(dbus_conn, "com.netf.daemon",
                                  DBUS_NAME_FLAG_DO_NOT_QUEUE, &err);
  if (ret == -1) {
    std::cerr << "Failed to register name: " << err.message << std::endl;
    dbus_error_free(&err);
    return false;
  }

  dbus_connection_set_exit_on_disconnect(dbus_conn, FALSE);
  return true;
}

void send_dbus_attack_signal(const std::string &attack_type,
                             const std::string &source_ip, int count) {
  if (!dbus_conn) {
    std::cerr << "D-Bus connection not initialized" << std::endl;
    return;
  }

  DBusMessage *msg = dbus_message_new_signal(
      "/com/netf/daemon", "com.netf.daemon", "AttackDetected");

  if (!msg) {
    std::cerr << "Failed to create D-Bus message" << std::endl;
    return;
  }

  const char *type_str = attack_type.c_str();
  const char *ip_str = source_ip.c_str();

  if (!dbus_message_append_args(msg, DBUS_TYPE_STRING, &type_str,
                                DBUS_TYPE_STRING, &ip_str, DBUS_TYPE_INT32,
                                &count, DBUS_TYPE_INVALID)) {
    std::cerr << "Failed to append message args" << std::endl;
    dbus_message_unref(msg);
    return;
  }

  if (!dbus_connection_send(dbus_conn, msg, nullptr)) {
    std::cerr << "Failed to send message" << std::endl;
  }

  dbus_connection_flush(dbus_conn);
  dbus_message_unref(msg);
}

void process_detected_attacks() {
  auto attacks = firewall::getDetectedAttacks();
  for (const auto &attack : attacks) {
    std::cout << "Sending attack alert: " << attack.type << " from "
              << attack.source_ip << std::endl;
    send_dbus_attack_signal(attack.type, attack.source_ip, attack.count);
  }
  firewall::clearDetectedAttacks();
}

int main() {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  if (system("sudo setcap cap_net_raw,cap_net_admin+eip $(realpath "
             "./NetF_deamon)") != 0) {
    std::cerr << "Warning: Failed to set capabilities" << std::endl;
  }

  if (!init_dbus_connection()) {
    std::cerr << "Failed to initialize D-Bus connection" << std::endl;
    return 1;
  }

  std::thread monitor_thread([]() {
    try {
      trafficmonitor::monitorTraffic("lo");
    } catch (const std::exception &e) {
      std::cerr << "Monitor error: " << e.what() << std::endl;
      stop_flag = 1;
    }
  });

  while (!stop_flag) {
    process_detected_attacks();
    usleep(100000); // 100ms
  }

  monitor_thread.join();

  if (dbus_conn) {
    dbus_connection_unref(dbus_conn);
  }

  std::cout << "NetF daemon stopped" << std::endl;
  return 0;
}