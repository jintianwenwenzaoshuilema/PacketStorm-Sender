#include "sender_window.h"
#include "ui_sender.h"
#include <QMessageBox>
#include <pcap.h>
#include <QDebug>

// 构造函数
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
    ui(new Ui::MainWindow),
    workerThread(nullptr), worker(nullptr)
{
    ui->setupUi(this);
    loadInterfaces();


    connect(ui->btnStartSend, &QPushButton::clicked, this, &MainWindow::onStartSendClicked);
    connect(ui->btnStopSend, &QPushButton::clicked, this, &MainWindow::onStopSendClicked);

    // === 新增：绑定协议切换信号 ===
    // 只要这几个按钮状态改变，就触发检查
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);

    // 初始化 UI 状态
    onProtoToggled();

}

MainWindow::~MainWindow() {
    g_is_sending = false;

    if (workerThread) {
        workerThread->terminate();
        workerThread->wait();
    }
    delete ui;
}

// === 新增：实现协议切换逻辑 ===
// MainWindow.cpp
void MainWindow::onProtoToggled() {
    // 1. 获取当前选中的协议状态
    bool isUdp  = ui->rbUdp->isChecked();
    bool isTcp  = ui->rbTcp->isChecked();
    bool isDns  = ui->rbDns->isChecked(); // 虽然目前没用，但保留逻辑
    // bool isIcmp = ui->rbIcmp->isChecked();

    // 2. 定义功能需求
    // UDP 和 TCP 需要显示并启用端口配置
    bool needPorts = isUdp || isTcp;

    // UDP 和 TCP 需要显示并启用载荷长度配置
    bool needPayloadLen = isUdp || isTcp;

    // 3. 执行 UI 更新 (同时控制 Visible 和 Enabled)

    // --- 源端口 ---
    ui->lblSPort->setVisible(needPorts);
    ui->spinSrcPort->setVisible(needPorts);
    ui->spinSrcPort->setEnabled(needPorts);

    // --- 目的端口 ---
    ui->lblDPort->setVisible(needPorts);
    ui->spinDstPort->setVisible(needPorts);
    ui->spinDstPort->setEnabled(needPorts);

    // --- 载荷长度 ---
    ui->lblLen->setVisible(needPayloadLen);
    ui->spinPktLen->setVisible(needPayloadLen);
    ui->spinPktLen->setEnabled(needPayloadLen); // <---【关键修复】添加这一行

    // --- 发包间隔 (始终显示且可用) ---
    ui->lblIntVal->setVisible(true);
    ui->spinInterval->setVisible(true);
    ui->spinInterval->setEnabled(true);

    ui->containerDns->setVisible(isDns);
    ui->containerTcpFlags->setVisible(isTcp);
}



void MainWindow::loadInterfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        ui->comboInterfaceTx->addItem("Error: " + QString(errbuf));
        return;
    }
    for(pcap_if_t *d=alldevs; d; d=d->next) {
        QString desc = d->description ? QString(d->description) : QString(d->name);
        QString name = QString(d->name);
        ui->comboInterfaceTx->addItem(desc, name);
    }
    pcap_freealldevs(alldevs);
}

// 修改 onStartSendClicked，读取参数
void MainWindow::onStartSendClicked() {
    if (workerThread && workerThread->isRunning()) return;

    ui->btnStartSend->setEnabled(false);
    ui->btnStopSend->setEnabled(true);
    ui->comboInterfaceTx->setEnabled(false);
    ui->grpParam->setEnabled(false);

    if (workerThread) { delete worker; delete workerThread; }

    workerThread = new QThread(this);
    worker = new PacketWorker();

    worker->interfaceName = ui->comboInterfaceTx->currentData().toString();
    worker->srcMac = ui->editSrcMac->text();
    worker->dstMac = ui->editDstMac->text();
    worker->srcIp  = ui->editSrcIp->text();
    worker->dstIp  = ui->editDstIp->text();
    worker->intervalUs = ui->spinInterval->value();

    // === 读取新增参数 ===
    worker->srcPort = ui->spinSrcPort->value();
    worker->dstPort = ui->spinDstPort->value();
    worker->payloadLen = ui->spinPktLen->value();

    worker->dnsDomain = ui->editDomain->text().trimmed();
    if (worker->dnsDomain.isEmpty()) worker->dnsDomain = "baidu.com";

    // === 新增：读取 Checkbox 组合 Flags ===
    int flags = 0;
    if (ui->rbTcp->isChecked()) {
        if (ui->chkFin->isChecked()) flags |= 0x01; // FIN
        if (ui->chkSyn->isChecked()) flags |= 0x02; // SYN
        if (ui->chkRst->isChecked()) flags |= 0x04; // RST
        if (ui->chkPsh->isChecked()) flags |= 0x08; // PSH
        if (ui->chkAck->isChecked()) flags |= 0x10; // ACK
        // URG=0x20 通常较少用，暂不加
    }
    worker->tcpFlags = flags; // 存入 worker

    if (ui->rbUdp->isChecked()) worker->pktType = UDP_PACKAGE;
    else if (ui->rbTcp->isChecked()) worker->pktType = TCP_PACKAGE;
    else if (ui->rbDns->isChecked()) worker->pktType = DNS_PACKAGE;
    else worker->pktType = ICMP_PACKAGE;

    worker->moveToThread(workerThread);
    connect(workerThread, &QThread::started, worker, &PacketWorker::doSendWork);
    connect(worker, &PacketWorker::workFinished, workerThread, &QThread::quit);
    connect(workerThread, &QThread::finished, this, [this]() {
        ui->btnStartSend->setEnabled(true);
        ui->btnStopSend->setEnabled(false);
        ui->comboInterfaceTx->setEnabled(true);
        ui->grpParam->setEnabled(true);
    });
    workerThread->start();
}

void MainWindow::onStopSendClicked() {
    g_is_sending = false;
    ui->btnStopSend->setEnabled(false);
}
