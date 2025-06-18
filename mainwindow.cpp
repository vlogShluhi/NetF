#include "mainwindow.h"
#include "./ui_mainwindow.h"
//SYN флуд
//sudo hping3 -S -p 80 --flood 127.0.0.1

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}
