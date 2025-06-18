#include "mainwindow.h"
#include "trafficmonitor.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    trafficmonitor::monitorTraffic("lo");
    MainWindow w;
    w.show();
    return a.exec();
}
