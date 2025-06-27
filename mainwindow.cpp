#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QChartView>
#include <QtCharts/QLegend>
#include <QtCharts/QValueAxis>
#include <QtCharts/QBarCategoryAxis>
#include <QStringList>
#include <QDateTime>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QTableWidget>
#include <QHeaderView>
#include <QPushButton>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("Network Firewall Monitor");
    resize(1000, 700);

    // Инициализация счетчиков атак
    attackCounts["UDP flood"] = 0;
    attackCounts["ICMP flood"] = 0;
    attackCounts["SYN flood"] = 0;
    attackCounts["FIN flood"] = 0;
    attackCounts["Null Scan"] = 0;
    attackCounts["Xmas Scan"] = 0;
    attackCounts["SSH bruteforce"] = 0;
    attackCounts["Port Scan"] = 0;

    setupCharts();
    setupUI();
    setupDBusConnection();

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateCharts);
    updateTimer->start(1000);

    this->setAttribute(Qt::WA_DeleteOnClose);
    this->show();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupDBusConnection()
{
    if (!QDBusConnection::sessionBus().isConnected()) {
        qWarning("Cannot connect to the D-Bus session bus.");
        return;
    }

    bool connected = QDBusConnection::sessionBus().connect(
        "com.netf.daemon",
        "/com/netf/daemon",
        "com.netf.daemon",
        "AttackDetected",
        this,
        SLOT(handleAttackDetected(QString,QString,int)));

    if (!connected) {
        qWarning("Failed to connect to AttackDetected signal.");
    }
}

void MainWindow::handleAttackDetected(const QString &type, const QString &source_ip, int count)
{
    QDateTime currentTime = QDateTime::currentDateTime();


    if (attackCounts.contains(type)) {
        attackCounts[type] = count;
    }


    bool found = false;
    for (int i = 0; i < attackersTable->rowCount(); ++i) {
        if (attackersTable->item(i, 0)->text() == source_ip) {
            attackersTable->item(i, 1)->setText(currentTime.toString("hh:mm:ss"));
            attackersTable->item(i, 2)->setText(QString::number(
                attackersTable->item(i, 2)->text().toInt() + count));
            found = true;
            break;
        }
    }

    if (!found) {
        int row = attackersTable->rowCount();
        attackersTable->insertRow(row);

        attackersTable->setItem(row, 0, new QTableWidgetItem(source_ip));
        attackersTable->setItem(row, 1, new QTableWidgetItem(currentTime.toString("hh:mm:ss")));
        attackersTable->setItem(row, 2, new QTableWidgetItem(QString::number(count)));

        QPushButton *banButton = new QPushButton("Ban");
        connect(banButton, &QPushButton::clicked, [this, source_ip]() {
            qDebug() << "Ban IP:" << source_ip;
        });
        attackersTable->setCellWidget(row, 3, banButton);
    }

    detailsDialog->updateLogs(type, source_ip, count);
}

void MainWindow::setupCharts()
{
    attackSet = new QBarSet("Attack Rate");
    *attackSet << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0;

    series = new QBarSeries();
    series->append(attackSet);

    attackChart = new QChart();
    attackChart->addSeries(series);
    attackChart->setTitle("Current Attack Rates");
    attackChart->setAnimationOptions(QChart::SeriesAnimations);
    attackChart->legend()->setVisible(true);
    attackChart->legend()->setAlignment(Qt::AlignBottom);

    QStringList categories;
    categories << "UDP" << "ICMP" << "SYN" << "FIN" << "Null" << "Xmas" << "SSH" << "PortScan";

    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append(categories);
    attackChart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    QValueAxis *axisY = new QValueAxis();
    axisY->setRange(0, 100);
    axisY->setLabelFormat("%d");
    axisY->setTitleText("Packets/sec");
    attackChart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);

    chartView = new QChartView(attackChart);
    chartView->setRenderHint(QPainter::Antialiasing);
}

void MainWindow::setupUI()
{
    QWidget *centralWidget = new QWidget(this);
    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);

    // Левая часть - график
    QVBoxLayout *leftLayout = new QVBoxLayout();
    chartView->setParent(centralWidget);
    chartView->setMinimumSize(500, 400);
    leftLayout->addWidget(chartView);

    detailsButton = new QPushButton("View Attack Details", this);
    connect(detailsButton, &QPushButton::clicked, this, &MainWindow::showAttackDetails);
    leftLayout->addWidget(detailsButton);

    QVBoxLayout *rightLayout = new QVBoxLayout();

    QLabel *attackersLabel = new QLabel("Attackers List:");
    rightLayout->addWidget(attackersLabel);

    attackersTable = new QTableWidget(0, 4, this);
    attackersTable->setHorizontalHeaderLabels({"IP Address", "Last Activity", "Count", "Action"});
    attackersTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    attackersTable->verticalHeader()->setVisible(false);
    rightLayout->addWidget(attackersTable);

    mainLayout->addLayout(leftLayout);
    mainLayout->addLayout(rightLayout);

    setCentralWidget(centralWidget);
    centralWidget->show();

    detailsDialog = new AttackDetailsDialog(this);
}

void MainWindow::updateCharts()
{
    attackSet->replace(0, attackCounts["UDP flood"]);
    attackSet->replace(1, attackCounts["ICMP flood"]);
    attackSet->replace(2, attackCounts["SYN flood"]);
    attackSet->replace(3, attackCounts["FIN flood"]);
    attackSet->replace(4, attackCounts["Null Scan"]);
    attackSet->replace(5, attackCounts["Xmas Scan"]);
    attackSet->replace(6, attackCounts["SSH bruteforce"]);
    attackSet->replace(7, attackCounts["Port Scan"]);

    for (auto& count : attackCounts) {
        count = 0;
    }
}

void MainWindow::showAttackDetails()
{
    detailsDialog->show();
}

AttackDetailsDialog::AttackDetailsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Attack Details");
    resize(1200, 600);
    setupUI();
}

void AttackDetailsDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    tabWidget = new QTabWidget(this);

    generalLog = new QTextEdit();
    generalLog->setReadOnly(true);
    tabWidget->addTab(generalLog, "General Log");

    udpLog = new QTextEdit();
    udpLog->setReadOnly(true);
    tabWidget->addTab(udpLog, "UDP Flood");

    icmpLog = new QTextEdit();
    icmpLog->setReadOnly(true);
    tabWidget->addTab(icmpLog, "ICMP Flood");

    synLog = new QTextEdit();
    synLog->setReadOnly(true);
    tabWidget->addTab(synLog, "SYN Flood");

    finLog = new QTextEdit();
    finLog->setReadOnly(true);
    tabWidget->addTab(finLog, "FIN Flood");

    nullScanLog = new QTextEdit();
    nullScanLog->setReadOnly(true);
    tabWidget->addTab(nullScanLog, "Null Scan");

    xmasScanLog = new QTextEdit();
    xmasScanLog->setReadOnly(true);
    tabWidget->addTab(xmasScanLog, "Xmas Scan");

    sshLog = new QTextEdit();
    sshLog->setReadOnly(true);
    tabWidget->addTab(sshLog, "SSH Attacks");

    portScanLog = new QTextEdit();
    portScanLog->setReadOnly(true);
    tabWidget->addTab(portScanLog, "Port Scan");

    mainLayout->addWidget(tabWidget);

    QPushButton *clearButton = new QPushButton("Clear Logs", this);
    connect(clearButton, &QPushButton::clicked, [this]() {
        generalLog->clear();
        udpLog->clear();
        icmpLog->clear();
        synLog->clear();
        finLog->clear();
        nullScanLog->clear();
        xmasScanLog->clear();
        sshLog->clear();
        portScanLog->clear();
    });

    QPushButton *closeButton = new QPushButton("Close", this);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::close);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(clearButton);
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);

    setLayout(mainLayout);
}

void AttackDetailsDialog::updateLogs(const QString &type, const QString &source_ip, int count)
{
    QDateTime currentTime = QDateTime::currentDateTime();
    QString logEntry = QString("[%1] %2 detected from %3 (rate: %4/sec)")
                           .arg(currentTime.toString("hh:mm:ss"))
                           .arg(type)
                           .arg(source_ip)
                           .arg(count);

    generalLog->append(logEntry);

    if (type == "UDP flood") {
        udpLog->append(logEntry);
    } else if (type == "ICMP flood") {
        icmpLog->append(logEntry);
    } else if (type == "SYN flood") {
        synLog->append(logEntry);
    } else if (type == "FIN flood") {
        finLog->append(logEntry);
    } else if (type == "Null Scan") {
        nullScanLog->append(logEntry);
    } else if (type == "Xmas Scan") {
        xmasScanLog->append(logEntry);
    } else if (type.contains("SSH")) {
        sshLog->append(logEntry);
    } else if (type.contains("Port Scan")) {
        portScanLog->append(logEntry);
    }
}
