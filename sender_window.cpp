#include "sender_window.h"
#include "ui_sender.h"
#include <QMessageBox>
#include <pcap.h>
#include <QDebug>

// 构造函数
// === 1. 构造函数 (完整内容) ===
MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
    ui(new Ui::MainWindow),
    workerThread(nullptr), worker(nullptr)
{
    ui->setupUi(this);
    loadInterfaces();

    // 基础按钮连接
    connect(ui->btnStartSend, &QPushButton::clicked, this, &MainWindow::onStartSendClicked);
    connect(ui->btnStopSend, &QPushButton::clicked, this, &MainWindow::onStopSendClicked);

    // 协议切换连接
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);

    // === 新增：载荷模式切换连接 ===
    // 假设你在 UI 中添加了 rbPayRandom, rbPayFixed, rbPayCustom
    connect(ui->rbPayRandom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayFixed, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayCustom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);

    // === 新增：自定义文本变化自动计算长度 ===
    // 假设自定义输入框叫 editCustomData
    connect(ui->editCustomData, &QLineEdit::textChanged, this, [this](const QString &text){
        if(ui->rbPayCustom->isChecked()) {
            // 自动更新长度，并设为只读
            ui->spinPktLen->setValue(text.toUtf8().length());
        }
    });

    // 初始化界面状态
    onProtoToggled();
    onPayloadModeChanged();
}

MainWindow::~MainWindow() {
    g_is_sending = false;

    if (workerThread) {
        workerThread->terminate();
        workerThread->wait();
    }
    delete ui;
}


// === 2. 新增：onPayloadModeChanged (完整内容) ===
void MainWindow::onPayloadModeChanged() {
    bool isFixed  = ui->rbPayFixed->isChecked();
    bool isCustom = ui->rbPayCustom->isChecked();

    // 控制固定值输入框显示
    ui->lblFixVal->setVisible(isFixed);
    ui->spinFixVal->setVisible(isFixed);

    // 控制自定义文本框显示
    ui->editCustomData->setVisible(isCustom);

    // 长度框控制逻辑
    if (isCustom) {
        // 自定义模式下，长度由文本自动决定，用户不能改
        ui->spinPktLen->setReadOnly(true);
        ui->spinPktLen->setStyleSheet("background-color: #333; color: #888;"); // 变暗提示
        // 立即更新一次当前长度
        ui->spinPktLen->setValue(ui->editCustomData->text().toUtf8().length());
    } else {
        // 其他模式下，用户可以自由指定长度
        ui->spinPktLen->setReadOnly(false);
        ui->spinPktLen->setStyleSheet(""); // 恢复默认样式
    }
}

// 替换 sender_window.cpp 中的 onProtoToggled 函数
void MainWindow::onProtoToggled() {
    // 1. 获取当前选中的协议状态
    bool isUdp  = ui->rbUdp->isChecked();
    bool isTcp  = ui->rbTcp->isChecked();
    bool isDns  = ui->rbDns->isChecked();

    // 2. 定义显示规则
    // 只有 UDP 和 TCP 允许用户自定义载荷内容和端口
    bool showPayloadOpts = isUdp || isTcp;
    bool showPorts = isUdp || isTcp;

    // 3. 执行 UI 更新

    // --- 端口设置显隐 ---
    ui->lblSPort->setVisible(showPorts);
    ui->spinSrcPort->setVisible(showPorts);
    ui->spinSrcPort->setEnabled(showPorts);

    ui->lblDPort->setVisible(showPorts);
    ui->spinDstPort->setVisible(showPorts);
    ui->spinDstPort->setEnabled(showPorts);

    // --- 载荷配置区域 (Payload Options) 显隐 ---
    // 这是你新加的 GroupBox，直接控制它即可整体隐藏
    ui->grpPayload->setVisible(showPayloadOpts);

    // --- 协议专属面板显隐 ---
    // DNS 面板 (只在 DNS 模式显示)
    ui->containerDns->setVisible(isDns);

    // TCP Flags 面板 (只在 TCP 模式显示)
    ui->containerTcpFlags->setVisible(isTcp);

    // --- 发包间隔 (始终显示) ---
    ui->lblIntVal->setVisible(true);
    ui->spinInterval->setVisible(true);
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
// === 3. 修改：onStartSendClicked (完整内容) ===
void MainWindow::onStartSendClicked() {
    if (workerThread && workerThread->isRunning()) return;

    ui->btnStartSend->setEnabled(false);
    ui->btnStopSend->setEnabled(true);
    ui->comboInterfaceTx->setEnabled(false);
    ui->grpParam->setEnabled(false);
    ui->grpPayload->setEnabled(false); // 禁用载荷配置

    if (workerThread) { delete worker; delete workerThread; }

    workerThread = new QThread(this);
    worker = new PacketWorker();

    // === 填充 SenderConfig 结构体 ===
    memset(&worker->config, 0, sizeof(SenderConfig)); // 初始化清零

    // 1. 基础参数
    std::string dev = ui->comboInterfaceTx->currentData().toString().toStdString();
    strncpy(worker->config.dev_name, dev.c_str(), sizeof(worker->config.dev_name) - 1);

    // MAC 和 IP 解析 lambda
    auto parseMac = [](QString s, unsigned char* buf){
        static const QRegularExpression regex("[:-]");
        QStringList p = s.split(regex);
        for(int i=0; i<6 && i<p.size(); ++i) buf[i] = p[i].toUInt(nullptr, 16);
    };
    auto parseIp = [](QString s, unsigned char* buf){
        QStringList p = s.split('.');
        for(int i=0; i<4 && i<p.size(); ++i) buf[i] = p[i].toUInt();
    };

    parseMac(ui->editSrcMac->text(), worker->config.src_mac);
    parseMac(ui->editDstMac->text(), worker->config.des_mac);
    parseIp(ui->editSrcIp->text(), worker->config.src_ip);
    parseIp(ui->editDstIp->text(), worker->config.des_ip);

    // 2. 传输控制
    worker->config.send_interval_us = ui->spinInterval->value();
    worker->config.src_port = ui->spinSrcPort->value();
    worker->config.dst_port = ui->spinDstPort->value();

    if (ui->rbUdp->isChecked()) worker->config.packet_type = UDP_PACKAGE;
    else if (ui->rbTcp->isChecked()) worker->config.packet_type = TCP_PACKAGE;
    else if (ui->rbDns->isChecked()) worker->config.packet_type = DNS_PACKAGE;
    else worker->config.packet_type = ICMP_PACKAGE;

    // TCP Flags
    if (ui->rbTcp->isChecked()) {
        int flags = 0;
        if (ui->chkFin->isChecked()) flags |= 0x01;
        if (ui->chkSyn->isChecked()) flags |= 0x02;
        if (ui->chkRst->isChecked()) flags |= 0x04;
        if (ui->chkPsh->isChecked()) flags |= 0x08;
        if (ui->chkAck->isChecked()) flags |= 0x10;
        worker->config.tcp_flags = flags;
    }

    // DNS Domain
    std::string domain = ui->editDomain->text().toStdString();
    strncpy(worker->config.dns_domain, domain.c_str(), sizeof(worker->config.dns_domain) - 1);

    // === 3. 载荷参数设置 ===
    worker->config.payload_len = ui->spinPktLen->value();

    if (ui->rbPayFixed->isChecked()) {
        worker->config.payload_mode = PAYLOAD_FIXED;
        worker->config.fixed_byte_val = (unsigned char)ui->spinFixVal->value();
    }
    else if (ui->rbPayCustom->isChecked()) {
        worker->config.payload_mode = PAYLOAD_CUSTOM;
        // 关键：将 UI 字符串保存到 worker 的 QByteArray 中，保证生命周期
        worker->customDataBuffer = ui->editCustomData->text().toUtf8();
        // 指针赋值将在 doSendWork 中进行
    }
    else {
        worker->config.payload_mode = PAYLOAD_RANDOM;
    }

    worker->moveToThread(workerThread);
    connect(workerThread, &QThread::started, worker, &PacketWorker::doSendWork);
    connect(worker, &PacketWorker::workFinished, workerThread, &QThread::quit);
    connect(workerThread, &QThread::finished, this, [this]() {
        ui->btnStartSend->setEnabled(true);
        ui->btnStopSend->setEnabled(false);
        ui->comboInterfaceTx->setEnabled(true);
        ui->grpParam->setEnabled(true);
        ui->grpPayload->setEnabled(true); // 恢复载荷配置
    });
    workerThread->start();
}

void MainWindow::onStopSendClicked() {
    g_is_sending = false;
    ui->btnStopSend->setEnabled(false);
}
