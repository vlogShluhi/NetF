#include "mainwindow.h"
#include "trafficmonitor.h"
#include <QApplication>
//sudo hping3 -S -p 80 --flood 127.0.0.1 SYN-flood
//sudo hping3 -F -p 80 --flood 127.0.0.1 FIN-flood
//sudo hping3 -Y -p 80 --flood 127.0.0.1 Null-can
//sudo hping3 --udp -p 53 --flood 127.0.0.1 UDP-flood
//sudo hping3 --icmp --flood 127.0.0.1 ICMP-flood
//sudo hping3 -F -P -U -p 80 --flood 127.0.0.1 Xmas-scan
//sudo hping3 -S -p 22 --flood 127.0.0.1 SSH-connect-flood
//sudo hping3 -p 22 -A -d 100 --flood 127.0.0.1 SSH-bruteforce
//for port in {1..50}; do sudo hping3 -S -p $port -c 1 127.0.0.1; done Port Scan
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    trafficmonitor::monitorTraffic("lo");
    MainWindow w;
    w.show();
    return a.exec();
}
