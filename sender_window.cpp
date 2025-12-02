#include "sender_window.h"
#include "ui_sender.h"
#include <QMessageBox>
#include <pcap.h>
#include <QDebug>

// ============================================================================
// [重要] 初始化 PacketWorker 的静态成员变量
// 必须在 cpp 文件中定义，否则链接时会报错 "undefined reference"
// ============================================================================
PacketWorker* PacketWorker::m_instance = nullptr;

// ============================================================================
//  增强版 SpinBox (保持不变)
// ============================================================================
class CommaSpinBox : public QSpinBox {
public:
    CommaSpinBox(QWidget* parent = nullptr) : QSpinBox(parent) {
        QLocale loc(QLocale::English, QLocale::UnitedStates);
        setLocale(loc);
        setGroupSeparatorShown(true);
    }
protected:
    int valueFromText(const QString &text) const override {
        QString t = text; t.remove(','); return t.toInt();
    }
    QString textFromValue(int val) const override {
        return locale().toString(val);
    }
    QValidator::State validate(QString &text, int &pos) const override {
        int digitsBefore = 0;
        for(int i=0; i<pos; ++i) if(text[i].isDigit()) digitsBefore++;
        QString raw = text;
        static const QRegularExpression regex("[^0-9]");
        raw.remove(regex);
        if(raw.isEmpty()) return QValidator::Intermediate;
        QString formatted = locale().toString(raw.toLongLong());
        if(text != formatted) {
            text = formatted;
            int newPos = 0;
            int digitsSeen = 0;
            while(newPos < text.length() && digitsSeen < digitsBefore) {
                if(text[newPos].isDigit()) digitsSeen++;
                newPos++;
            }
            pos = newPos;
        }
        return QValidator::Acceptable;
    }
};

// ============================================================================
//  MainWindow 实现
// ============================================================================

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
    ui(new Ui::MainWindow),
    workerThread(nullptr), worker(nullptr),
    stopBtnAnim(nullptr), stopBtnEffect(nullptr)
// 注意：不再初始化 statsTimer，因为已改用信号驱动
{
    ui->setupUi(this);

    // ====================================================================
    // 1. 【防崩溃核心】优先替换控件
    // ====================================================================
    CommaSpinBox* newSpin = new CommaSpinBox(this);
    newSpin->setMinimum(ui->spinInterval->minimum());
    newSpin->setMaximum(ui->spinInterval->maximum());
    newSpin->setValue(ui->spinInterval->value());
    newSpin->setSingleStep(ui->spinInterval->singleStep());
    newSpin->setObjectName("spinInterval");
    newSpin->setFont(ui->spinInterval->font());
    newSpin->setStyleSheet(ui->spinInterval->styleSheet());

    ui->formLayout_Param->replaceWidget(ui->spinInterval, newSpin);
    delete ui->spinInterval;
    ui->spinInterval = newSpin;

    // ====================================================================
    // 2. 基础初始化
    // ====================================================================
    ui->editDomain->setStyleSheet("");
    loadInterfaces();

    QRegularExpression ipRegex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    QRegularExpressionValidator *ipVal = new QRegularExpressionValidator(ipRegex, this);
    ui->editSrcIp->setValidator(ipVal);
    ui->editDstIp->setValidator(ipVal);

    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    QRegularExpressionValidator *macVal = new QRegularExpressionValidator(macRegex, this);
    ui->editSrcMac->setValidator(macVal);
    ui->editDstMac->setValidator(macVal);

    ui->editSrcMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");
    ui->editDstMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");

    // ====================================================================
    // 3. 底部状态栏管理 (使用 Struct 统一管理)
    // ====================================================================
    QStatusBar *bar = new QStatusBar(this);
    setStatusBar(bar);

    // 调用 Dashboard 初始化，样式和标签都在 sender_window.h 中定义好了
    m_dashboard.init(bar, this);

    // ====================================================================
    // 4. 中间 PPS 预估标签
    // ====================================================================
    lblTargetPPS = new QLabel("Rate: -- pps", this);
    lblTargetPPS->setStyleSheet("color: #FFB74D; font-size: 11px;");
    ui->formLayout_Param->addRow("", lblTargetPPS);

    // ====================================================================
    // 5. 信号连接
    // ====================================================================
    connect(ui->spinInterval, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int intervalUs){
        if (intervalUs <= 0) {
            lblTargetPPS->setText("Target: Max Speed");
        } else {
            double pps = 1000000.0 / (double)intervalUs;
            QString ppsText;
            if (pps >= 1000000) ppsText = QString::number(pps / 1000000.0, 'f', 2) + " Mpps";
            else if (pps >= 1000) ppsText = QString::number(pps / 1000.0, 'f', 1) + " kpps";
            else ppsText = QString::number((int)pps) + " pps";
            lblTargetPPS->setText("Target: " + ppsText);
        }
    });
    emit ui->spinInterval->valueChanged(ui->spinInterval->value());

    // 注意：不再连接 statsTimer，改在 onStartSendClicked 连接 worker 信号

    connect(ui->btnStartSend, &QPushButton::clicked, this, &MainWindow::onStartSendClicked);
    connect(ui->btnStopSend, &QPushButton::clicked, this, &MainWindow::onStopSendClicked);
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbPayRandom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayFixed, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayCustom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);

    connect(ui->editCustomData, &QLineEdit::textChanged, this, [this](const QString &text){
        if(ui->rbPayCustom->isChecked()) {
            ui->spinPktLen->setValue(text.toUtf8().length());
        }
    });

    onProtoToggled();
    onPayloadModeChanged();
}

MainWindow::~MainWindow() {
    g_is_sending = false;
    if (workerThread) {
        workerThread->quit();
        workerThread->wait();
    }
    if (stopBtnAnim) {
        stopBtnAnim->stop();
        delete stopBtnAnim;
    }
    delete ui;
}

void MainWindow::onPayloadModeChanged() {
    bool isFixed  = ui->rbPayFixed->isChecked();
    bool isCustom = ui->rbPayCustom->isChecked();

    ui->lblFixVal->setVisible(isFixed);
    ui->spinFixVal->setVisible(isFixed);
    ui->editCustomData->setVisible(isCustom);

    if (isCustom) {
        ui->spinPktLen->setReadOnly(true);
        ui->spinPktLen->setStyleSheet("background-color: #1a202c; color: #718096; border: 1px dashed #2d3748;");
        ui->spinPktLen->setValue(ui->editCustomData->text().toUtf8().length());
    } else {
        ui->spinPktLen->setReadOnly(false);
        ui->spinPktLen->setStyleSheet("");
    }
}

void MainWindow::onProtoToggled() {
    bool isUdp  = ui->rbUdp->isChecked();
    bool isTcp  = ui->rbTcp->isChecked();
    bool isDns  = ui->rbDns->isChecked();

    bool showPayloadOpts = isUdp || isTcp;
    bool showPorts = isUdp || isTcp;

    ui->lblSPort->setVisible(showPorts);
    ui->spinSrcPort->setVisible(showPorts);
    ui->spinSrcPort->setEnabled(showPorts);

    ui->lblDPort->setVisible(showPorts);
    ui->spinDstPort->setVisible(showPorts);
    ui->spinDstPort->setEnabled(showPorts);

    ui->grpPayload->setVisible(showPayloadOpts);
    ui->containerDns->setVisible(isDns);
    ui->containerTcpFlags->setVisible(isTcp);

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

// ============================================================================
// 1. 点击开始发送
// ============================================================================
void MainWindow::onStartSendClicked() {
    // 防止重复点击
    if (workerThread && workerThread->isRunning()) return;

    // === [1] 重置计数器和速率基准 ===
    g_total_sent = 0;
    g_total_bytes = 0;

    lastTotalSent = 0;
    lastTotalBytes = 0;

    // 启动高精度计时器 (用于计算 PPS)
    rateTimer.start();

    // 立即重置界面显示为 0
    m_dashboard.updateUI(0, 0, 0, 0);

    // === [2] 锁定 UI 控件 ===
    ui->btnStartSend->setEnabled(false);
    ui->btnStopSend->setEnabled(true);
    ui->comboInterfaceTx->setEnabled(false);
    ui->grpParam->setEnabled(false);
    ui->grpPayload->setEnabled(false);
    ui->grpAddr->setEnabled(false);

    // === [3] 准备线程和 Worker ===
    if (workerThread) { delete worker; delete workerThread; }
    workerThread = new QThread(this);
    worker = new PacketWorker();

    // === [4] 配置 Worker 参数 ===
    memset(&worker->config, 0, sizeof(SenderConfig));

    std::string dev = ui->comboInterfaceTx->currentData().toString().toStdString();
    strncpy(worker->config.dev_name, dev.c_str(), sizeof(worker->config.dev_name) - 1);

    // 解析 MAC 和 IP
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

    worker->config.send_interval_us = ui->spinInterval->value();
    worker->config.src_port = ui->spinSrcPort->value();
    worker->config.dst_port = ui->spinDstPort->value();

    if (ui->rbUdp->isChecked()) worker->config.packet_type = UDP_PACKAGE;
    else if (ui->rbTcp->isChecked()) worker->config.packet_type = TCP_PACKAGE;
    else if (ui->rbDns->isChecked()) worker->config.packet_type = DNS_PACKAGE;
    else worker->config.packet_type = ICMP_PACKAGE;

    if (ui->rbTcp->isChecked()) {
        int flags = 0;
        if (ui->chkFin->isChecked()) flags |= 0x01;
        if (ui->chkSyn->isChecked()) flags |= 0x02;
        if (ui->chkRst->isChecked()) flags |= 0x04;
        if (ui->chkPsh->isChecked()) flags |= 0x08;
        if (ui->chkAck->isChecked()) flags |= 0x10;
        worker->config.tcp_flags = flags;
    }

    std::string domain = ui->editDomain->text().toStdString();
    strncpy(worker->config.dns_domain, domain.c_str(), sizeof(worker->config.dns_domain) - 1);
    worker->config.payload_len = ui->spinPktLen->value();

    if (ui->rbPayFixed->isChecked()) {
        worker->config.payload_mode = PAYLOAD_FIXED;
        worker->config.fixed_byte_val = (unsigned char)ui->spinFixVal->value();
    }
    else if (ui->rbPayCustom->isChecked()) {
        worker->config.payload_mode = PAYLOAD_CUSTOM;
        worker->customDataBuffer = ui->editCustomData->text().toUtf8();
    }
    else {
        worker->config.payload_mode = PAYLOAD_RANDOM;
    }

    // === [5] 连接信号与槽 ===
    worker->moveToThread(workerThread);
    connect(workerThread, &QThread::started, worker, &PacketWorker::doSendWork);
    connect(worker, &PacketWorker::workFinished, workerThread, &QThread::quit);

    // 【关键】连接统计信号 -> 界面更新槽 (使用 QueuedConnection 确保跨线程安全)
    connect(worker, &PacketWorker::statsUpdated, this, &MainWindow::updateStats, Qt::QueuedConnection);

    // 线程结束后的清理
    connect(workerThread, &QThread::finished, this, [this]() {
        ui->btnStartSend->setEnabled(true);
        ui->btnStopSend->setEnabled(false);
        ui->comboInterfaceTx->setEnabled(true);
        ui->grpParam->setEnabled(true);
        ui->grpPayload->setEnabled(true);
        ui->grpAddr->setEnabled(true);
    });

    // === [6] 启动线程 ===
    workerThread->start();

    // === [7] 启动 UI 动画 ===
    if (!stopBtnEffect) {
        stopBtnEffect = new QGraphicsDropShadowEffect(this);
        stopBtnEffect->setOffset(0, 0);
        stopBtnEffect->setColor(QColor(255, 0, 0, 255));
        stopBtnEffect->setBlurRadius(0);
        ui->btnStopSend->setGraphicsEffect(stopBtnEffect);
    }
    if (!stopBtnAnim) {
        stopBtnAnim = new QPropertyAnimation(stopBtnEffect, "blurRadius", this);
        stopBtnAnim->setDuration(1500);
        stopBtnAnim->setStartValue(20);
        stopBtnAnim->setEndValue(60);
        stopBtnAnim->setEasingCurve(QEasingCurve::InOutSine);
        stopBtnAnim->setLoopCount(-1);
    }
    stopBtnAnim->start();
    ui->btnStopSend->setFocus();
}

// ============================================================================
// 2. 点击停止发送
// ============================================================================
void MainWindow::onStopSendClicked() {
    g_is_sending = false;
    ui->btnStopSend->setEnabled(false);

    // 手动调用一次更新，确保显示最终的统计结果 (防止最后一次信号未送达)
    updateStats(g_total_sent.load(), g_total_bytes.load());

    if (stopBtnAnim) {
        stopBtnAnim->stop();
        delete stopBtnAnim;
        stopBtnAnim = nullptr;
    }
    if (stopBtnEffect) {
        ui->btnStopSend->setGraphicsEffect(nullptr);
        stopBtnEffect = nullptr;
    }
}

// ============================================================================
// 3. 直接更新统计 (响应 Worker 的信号)
// ============================================================================
void MainWindow::updateStats(uint64_t currSent, uint64_t currBytes) {
    // 1. 获取距离上一次更新的时间间隔 (ms)
    qint64 elapsedMs = rateTimer.restart();

    // 防止除以 0
    if (elapsedMs < 1) elapsedMs = 1;

    // 2. 计算本周期内的增量
    uint64_t diffSent = (currSent >= lastTotalSent) ? (currSent - lastTotalSent) : 0;
    uint64_t diffBytes = (currBytes >= lastTotalBytes) ? (currBytes - lastTotalBytes) : 0;

    // 3. 更新基准值，供下一次计算使用
    lastTotalSent = currSent;
    lastTotalBytes = currBytes;

    // 4. 计算速率 (每秒)
    double pps = (double)diffSent * 1000.0 / elapsedMs;
    double bps = (double)diffBytes * 1000.0 / elapsedMs;

    // 5. 委托 Dashboard 更新界面
    m_dashboard.updateUI(currSent, currBytes, pps, bps);
}
