#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTimer>

// Подключаем заголовки Qt Charts
#include <QtCharts>

// Убедитесь, что QT_CHARTS_USE_NAMESPACE определен
#ifndef QT_CHARTS_USE_NAMESPACE
#define QT_CHARTS_USE_NAMESPACE
#endif

QT_CHARTS_USE_NAMESPACE

    QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class AttackDetailsDialog;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void updateCharts();
    void showAttackDetails();

private:
    Ui::MainWindow *ui;
    QChart *attackChart;
    QChartView *chartView;
    QBarSeries *series;
    QBarSet *attackSet;
    QPushButton *detailsButton;
    AttackDetailsDialog *detailsDialog;
    QTimer *updateTimer;

    void setupCharts();
    void setupUI();
};

class AttackDetailsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AttackDetailsDialog(QWidget *parent = nullptr);
    void updateLogs();

private:
    QTabWidget *tabWidget;
    QTextEdit *generalLog;
    QTextEdit *udpLog;
    QTextEdit *icmpLog;
    QTextEdit *synLog;
    QTextEdit *finLog;
    QTextEdit *nullScanLog;
    QTextEdit *xmasScanLog;
    QTextEdit *sshLog;
    QTextEdit *portScanLog;
    QPushButton *closeButton;

    void setupUI();
};

#endif // MAINWINDOW_H
