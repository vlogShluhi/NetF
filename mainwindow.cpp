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
#include <QRandomGenerator>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("Network Firewall Monitor");
    resize(800, 600);

    // Сначала создаем графики
    setupCharts();

    // Затем настраиваем UI
    setupUI();

    // Настройка таймера
    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &MainWindow::updateCharts);
    updateTimer->start(5000);

    // Гарантируем отображение
    this->setAttribute(Qt::WA_DeleteOnClose);
    this->show();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupCharts()
{
    attackSet = new QBarSet("Attack Count");
    *attackSet << 1 << 1 << 1 << 1 << 1 << 1 << 1 << 1; // Начальные значения не нулевые

    series = new QBarSeries();
    series->append(attackSet);

    attackChart = new QChart();
    attackChart->addSeries(series);
    attackChart->setTitle("Network Attack Statistics");
    attackChart->setAnimationOptions(QChart::SeriesAnimations);
    attackChart->legend()->setVisible(true);
    attackChart->legend()->setAlignment(Qt::AlignBottom);

    // Настройка осей
    QStringList categories;
    categories << "UDP" << "ICMP" << "SYN" << "FIN" << "Null" << "Xmas" << "SSH" << "PortScan";

    QBarCategoryAxis *axisX = new QBarCategoryAxis();
    axisX->append(categories);
    attackChart->addAxis(axisX, Qt::AlignBottom);
    series->attachAxis(axisX);

    QValueAxis *axisY = new QValueAxis();
    axisY->setRange(0, 10); // Явно задаем диапазон
    axisY->setLabelFormat("%d");
    axisY->setTitleText("Count");
    attackChart->addAxis(axisY, Qt::AlignLeft);
    series->attachAxis(axisY);

    chartView = new QChartView(attackChart);
    chartView->setRenderHint(QPainter::Antialiasing);
}

void MainWindow::setupUI()
{
    // Главный виджет и layout
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // Настройка chartView
    chartView->setParent(centralWidget); // Важно установить родителя
    chartView->setMinimumSize(600, 400);
    mainLayout->addWidget(chartView);

    // Кнопка деталей
    detailsButton = new QPushButton("View Attack Details", this);
    connect(detailsButton, &QPushButton::clicked, this, &MainWindow::showAttackDetails);
    mainLayout->addWidget(detailsButton);

    // Установка центрального виджета
    setCentralWidget(centralWidget);
    centralWidget->show(); // Явный вызов show()

    // Инициализация диалога
    detailsDialog = new AttackDetailsDialog(this);
}

void MainWindow::updateCharts()
{
    QRandomGenerator *rng = QRandomGenerator::global();

    // Обновляем данные
    attackSet->replace(0, rng->bounded(10));
    attackSet->replace(1, rng->bounded(10));
    attackSet->replace(2, rng->bounded(10));
    attackSet->replace(3, rng->bounded(10));
    attackSet->replace(4, rng->bounded(10));
    attackSet->replace(5, rng->bounded(10));
    attackSet->replace(6, rng->bounded(10));
    attackSet->replace(7, rng->bounded(10));

    // Явно обновляем график
    attackChart->update();
    chartView->update();
}
void MainWindow::showAttackDetails()
{
    detailsDialog->updateLogs();
    detailsDialog->show();
}

// AttackDetailsDialog implementation
AttackDetailsDialog::AttackDetailsDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Attack Details");
    resize(1000, 600);
    setupUI();
}

void AttackDetailsDialog::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Create tab widget
    tabWidget = new QTabWidget(this);

    // General log tab
    generalLog = new QTextEdit();
    generalLog->setReadOnly(true);
    tabWidget->addTab(generalLog, "General Log");

    // UDP attacks tab
    udpLog = new QTextEdit();
    udpLog->setReadOnly(true);
    tabWidget->addTab(udpLog, "UDP Flood");

    // ICMP attacks tab
    icmpLog = new QTextEdit();
    icmpLog->setReadOnly(true);
    tabWidget->addTab(icmpLog, "ICMP Flood");

    // SYN attacks tab
    synLog = new QTextEdit();
    synLog->setReadOnly(true);
    tabWidget->addTab(synLog, "SYN Flood");

    // FIN attacks tab
    finLog = new QTextEdit();
    finLog->setReadOnly(true);
    tabWidget->addTab(finLog, "FIN Flood");

    // Null scan tab
    nullScanLog = new QTextEdit();
    nullScanLog->setReadOnly(true);
    tabWidget->addTab(nullScanLog, "Null Scan");

    // Xmas scan tab
    xmasScanLog = new QTextEdit();
    xmasScanLog->setReadOnly(true);
    tabWidget->addTab(xmasScanLog, "Xmas Scan");

    // SSH attacks tab
    sshLog = new QTextEdit();
    sshLog->setReadOnly(true);
    tabWidget->addTab(sshLog, "SSH Attacks");

    // Port scan tab
    portScanLog = new QTextEdit();
    portScanLog->setReadOnly(true);
    tabWidget->addTab(portScanLog, "Port Scan");

    mainLayout->addWidget(tabWidget);

    // Close button
    closeButton = new QPushButton("Close", this);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::close);
    mainLayout->addWidget(closeButton);

    setLayout(mainLayout);
}

void AttackDetailsDialog::updateLogs()
{
    QDateTime currentTime = QDateTime::currentDateTime();

    // Update general log
    generalLog->append(QString("[%1] General network activity log...").arg(currentTime.toString()));

    // Update UDP log
    udpLog->append(QString("[%1] UDP flood detected from 192.168.1.%2")
                       .arg(currentTime.toString())
                       .arg(QRandomGenerator::global()->bounded(1, 254)));

    // Update ICMP log
    icmpLog->append(QString("[%1] ICMP flood detected from 192.168.1.%2")
                        .arg(currentTime.toString())
                        .arg(QRandomGenerator::global()->bounded(1, 254)));

    // Update other logs similarly...
    synLog->append(QString("[%1] SYN flood detected from 192.168.1.%2")
                       .arg(currentTime.toString())
                       .arg(QRandomGenerator::global()->bounded(1, 254)));

    finLog->append(QString("[%1] FIN flood detected from 192.168.1.%2")
                       .arg(currentTime.toString())
                       .arg(QRandomGenerator::global()->bounded(1, 254)));

    nullScanLog->append(QString("[%1] Null scan detected from 192.168.1.%2")
                            .arg(currentTime.toString())
                            .arg(QRandomGenerator::global()->bounded(1, 254)));

    xmasScanLog->append(QString("[%1] Xmas scan detected from 192.168.1.%2")
                            .arg(currentTime.toString())
                            .arg(QRandomGenerator::global()->bounded(1, 254)));

    sshLog->append(QString("[%1] SSH bruteforce attempt from 192.168.1.%2")
                       .arg(currentTime.toString())
                       .arg(QRandomGenerator::global()->bounded(1, 254)));

    portScanLog->append(QString("[%1] Port scan detected from 192.168.1.%2")
                            .arg(currentTime.toString())
                            .arg(QRandomGenerator::global()->bounded(1, 254)));
}
