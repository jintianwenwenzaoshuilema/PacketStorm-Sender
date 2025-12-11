#include "sender_window.h"
#include "ui_sender.h"
#include <QMessageBox>
#include <pcap.h>
#include <QDebug>
#include <QSettings>
#include <QDateTime>
#include <QScrollBar>
#include <thread>
#include <functional>
#include <QGraphicsLayout>

// ============================================================================
// Windows API 头文件与库链接
// ============================================================================
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

// 初始化静态成员
PacketWorker* PacketWorker::m_instance = nullptr;
SocketWorker* SocketWorker::m_instance = nullptr; // [新增] 初始化 SocketWorker

// ============================================================================
// SpinBox 增强版
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
// WinAPI 获取 MAC/IP
// ============================================================================
static bool GetAdapterInfoWinAPI(const QString& pcapName, QString& outMac, QString& outIp) {
#ifdef _WIN32
    int bracePos = pcapName.indexOf('{');
    if (bracePos == -1) return false;
    QString targetGuid = pcapName.mid(bracePos);

    ULONG outBufLen = 15000;
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
    if (pAdapterInfo == NULL) return false;

    DWORD dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
        if (pAdapterInfo == NULL) return false;
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    }

    bool found = false;
    if (dwRetVal == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            QString currentName = QString(pAdapter->AdapterName);
            if (targetGuid.compare(currentName, Qt::CaseInsensitive) == 0) {
                if (pAdapter->AddressLength == 6) {
                    outMac = QString("%1:%2:%3:%4:%5:%6")
                    .arg(pAdapter->Address[0], 2, 16, QChar('0'))
                        .arg(pAdapter->Address[1], 2, 16, QChar('0'))
                        .arg(pAdapter->Address[2], 2, 16, QChar('0'))
                        .arg(pAdapter->Address[3], 2, 16, QChar('0'))
                        .arg(pAdapter->Address[4], 2, 16, QChar('0'))
                        .arg(pAdapter->Address[5], 2, 16, QChar('0')).toUpper();
                }
                outIp = QString(pAdapter->IpAddressList.IpAddress.String);
                if (outIp == "0.0.0.0") outIp = "";
                found = true;
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    if (pAdapterInfo) free(pAdapterInfo);
    return found;
#else
    return false;
#endif
}

// ============================================================================
// MainWindow 实现
// ============================================================================

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
    ui(new Ui::MainWindow),
    workerThread(nullptr), worker(nullptr),
    stopBtnAnim(nullptr), stopBtnEffect(nullptr),
    sockThread(nullptr), sockWorker(nullptr) // [新增] 初始化右侧模块指针
{
    ui->setupUi(this);

    // 1. 替换 SpinBox
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

    ui->editDomain->setStyleSheet("");
    ui->txtLog->clear();
    appendLog("System initialized. Scanning interfaces...", 0);

    loadInterfaces();

    // 2. 验证器
    QRegularExpression ipRegex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    QRegularExpressionValidator *ipVal = new QRegularExpressionValidator(ipRegex, this);
    ui->editSrcIp->setValidator(ipVal);
    if (ui->editDstIp->lineEdit()) {
        ui->editDstIp->lineEdit()->setValidator(ipVal);
    }

    // [新增] 为右侧 Socket 模块的 IP 输入框添加验证器
    ui->editSockIp->setValidator(new QRegularExpressionValidator(ipRegex, this));

    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    QRegularExpressionValidator *macVal = new QRegularExpressionValidator(macRegex, this);
    ui->editSrcMac->setValidator(macVal);
    ui->editDstMac->setValidator(macVal);

    ui->editSrcMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");
    ui->editDstMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");

    // 3. 状态栏
    QStatusBar *bar = new QStatusBar(this);
    setStatusBar(bar);
    m_dashboard.init(bar, this);

    // 4. PPS 标签
    lblTargetPPS = new QLabel("Rate: -- pps", this);
    lblTargetPPS->setStyleSheet("color: #FFB74D; font-size: 11px;");
    ui->formLayout_Param->addRow("", lblTargetPPS);

    // 5. 信号连接
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

    connect(ui->btnStartSend, &QPushButton::clicked, this, &MainWindow::onStartSendClicked);
    connect(ui->btnStopSend, &QPushButton::clicked, this, &MainWindow::onStopSendClicked);
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbPayRandom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayFixed, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayCustom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->btnGetMac, &QPushButton::clicked, this, &MainWindow::onGetDstMacClicked);

    // [新增] 连接右侧 Socket 发送模块的信号
    connect(ui->btnSockStart, &QPushButton::clicked, this, &MainWindow::onSockStartClicked);
    connect(ui->btnSockStop, &QPushButton::clicked, this, &MainWindow::onSockStopClicked);

    connect(ui->editCustomData, &QLineEdit::textChanged, this, [this](const QString &text){
        if(ui->rbPayCustom->isChecked()) {
            ui->spinPktLen->setValue(text.toUtf8().length());
        }
    });

    // 6. 初始化图表
    setupChart();

    // 7. 加载配置
    loadHistory();
    loadConfig();

    onProtoToggled();
    onPayloadModeChanged();
    emit ui->spinInterval->valueChanged(ui->spinInterval->value());

    appendLog("System Ready. Configuration restored.", 1);
}


MainWindow::~MainWindow() {
    saveConfig();

    // 停止左侧 WinPcap 线程
    g_is_sending = false;
    if (workerThread) {
        workerThread->quit();
        workerThread->wait();
    }

    // [新增] 停止右侧 Socket 线程
    g_is_sock_sending = false;
    if (sockThread) {
        sockThread->quit();
        sockThread->wait();
    }

    if (stopBtnAnim) {
        stopBtnAnim->stop();
        delete stopBtnAnim;
    }
    delete ui;
}

// ============================================================================
// [新增] 右侧 Socket 模块实现 (OS Stack Sender)
// ============================================================================
void MainWindow::onSockStartClicked() {
    // 1. 安全检查：如果指针不为空且线程正在运行，则通过
    if (sockThread && sockThread->isRunning()) return;

    // UI 锁定逻辑...
    ui->btnSockStart->setEnabled(false);
    ui->btnSockStop->setEnabled(true);

    // 锁定控件...
    ui->grpSocketSender->findChild<QWidget*>("grpSockProto")->setEnabled(false);
    ui->editSockIp->setEnabled(false);
    ui->spinSockPort->setEnabled(false);
    ui->spinSockLen->setEnabled(false);
    ui->spinSockInt->setEnabled(false);
    if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
        ui->comboSockSrc->setEnabled(false);
    }

    // 重置数据...
    g_sock_total_sent = 0;
    g_sock_total_bytes = 0;
    rateTimer.start();
    lastTotalSent = 0;
    lastTotalBytes = 0;

    // 创建新线程对象
    sockThread = new QThread(this);
    sockWorker = new SocketWorker();

    // 配置赋值...
    std::string ip = ui->editSockIp->text().toStdString();
    memset(sockWorker->config.target_ip, 0, sizeof(sockWorker->config.target_ip));
    strncpy(sockWorker->config.target_ip, ip.c_str(), sizeof(sockWorker->config.target_ip)-1);

    memset(sockWorker->config.source_ip, 0, sizeof(sockWorker->config.source_ip));
    if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
        QString selectedPcapName = ui->comboSockSrc->currentData().toString();
        if (selectedPcapName.isEmpty()) {
            strcpy(sockWorker->config.source_ip, "0.0.0.0");
            appendLog("[SOCK] Routing: Auto (Default)", 0);
        } else {
            QString mac, srcIp;
            if (GetAdapterInfoWinAPI(selectedPcapName, mac, srcIp) && !srcIp.isEmpty() && srcIp != "0.0.0.0") {
                strncpy(sockWorker->config.source_ip, srcIp.toStdString().c_str(), sizeof(sockWorker->config.source_ip)-1);
                appendLog("[SOCK] Bound Interface: " + srcIp, 0);
            } else {
                strcpy(sockWorker->config.source_ip, "0.0.0.0");
                appendLog("[SOCK] Warning: Selected interface has no IPv4. Fallback to Auto.", 2);
            }
        }
    }

    sockWorker->config.target_port = ui->spinSockPort->value();
    sockWorker->config.is_udp = ui->rbSockUdp->isChecked();
    sockWorker->config.payload_len = ui->spinSockLen->value();
    sockWorker->config.interval_us = ui->spinSockInt->value();

    sockWorker->moveToThread(sockThread);

    // 连接信号
    connect(sockThread, &QThread::started, sockWorker, &SocketWorker::doWork);
    connect(sockWorker, &SocketWorker::workFinished, sockThread, &QThread::quit);
    connect(sockWorker, &SocketWorker::workFinished, sockWorker, &SocketWorker::deleteLater);
    connect(sockThread, &QThread::finished, sockThread, &QThread::deleteLater);
    connect(sockWorker, &SocketWorker::statsUpdated, this, &MainWindow::updateSockStats, Qt::QueuedConnection);
    connect(sockWorker, &SocketWorker::logUpdated, this, [this](QString msg, int level){
        this->appendLog(msg, level);
    }, Qt::QueuedConnection);

    // === [关键修复] 线程结束后的清理逻辑 ===
    connect(sockThread, &QThread::finished, this, [this](){
        ui->btnSockStart->setEnabled(true);
        ui->btnSockStop->setEnabled(false);
        ui->grpSocketSender->findChild<QWidget*>("grpSockProto")->setEnabled(true);
        ui->editSockIp->setEnabled(true);
        ui->spinSockPort->setEnabled(true);
        ui->spinSockLen->setEnabled(true);
        ui->spinSockInt->setEnabled(true);

        if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
            ui->comboSockSrc->setEnabled(true);
        }

        appendLog("[SOCK] Standard Sender stopped.", 0);

        // [这里是修复的核心] 将指针置空，防止下次点击时访问野指针
        sockThread = nullptr;
        sockWorker = nullptr;
    });

    sockThread->start();
    appendLog(QString("[SOCK] Started... Int: %1us").arg(sockWorker->config.interval_us), 1);
}

void MainWindow::onSockStopClicked() {
    // 设置停止标志，线程循环检测到后会退出
    g_is_sock_sending = false;
    ui->btnSockStop->setEnabled(false);
}

void MainWindow::updateSockStats(uint64_t sent, uint64_t bytes) {
    // 这里简单复用 updateStats 的逻辑
    // 注意：如果左侧 WinPcap 和右侧 Socket 同时发送，图表会跳变
    updateStats(sent, bytes);
}

// ============================================================================
// [修改] 初始化图表 (上下两个独立图表)
// ============================================================================
void MainWindow::setupChart() {
    // --- 通用样式设置 ---
    auto configChart = [](QChart* chart, const QString& title, const QString& colorHex) {
        chart->setTitle(title);
        chart->setAnimationOptions(QChart::NoAnimation);
        chart->setBackgroundVisible(false);
        chart->setTitleBrush(QBrush(QColor(colorHex)));
        chart->setTitleFont(QFont("JetBrains Mono", 9, QFont::Bold));
        chart->layout()->setContentsMargins(0, 0, 0, 0);
        chart->setBackgroundRoundness(0);
        chart->legend()->hide(); // 隐藏图例，因为标题已经说明了
    };

    auto configAxisX = [](QValueAxis* axis) {
        axis->setRange(0, 60);
        axis->setLabelFormat("%d");
        axis->setLabelsColor(QColor("#718096"));
        axis->setGridLineColor(QColor("#1c2333"));
    };

    auto configAxisY = [](QValueAxis* axis, const QString& colorHex, const QString& format) {
        axis->setLabelFormat(format); // "%d" or "%.1f"
        axis->setLabelsColor(QColor(colorHex));
        axis->setGridLineColor(QColor("#1c2333"));
    };

    // =========================================================
    // 1. 上半部分：PPS 图表 (绿色)
    // =========================================================
    chartPPS = new QChart();
    configChart(chartPPS, "Packet Rate (PPS)", "#00e676");

    seriesPPS = new QSplineSeries();
    QPen penPPS(QColor("#00e676"));
    penPPS.setWidth(2);
    seriesPPS->setPen(penPPS);
    chartPPS->addSeries(seriesPPS);

    axisX_PPS = new QValueAxis();
    configAxisX(axisX_PPS);
    chartPPS->addAxis(axisX_PPS, Qt::AlignBottom);
    seriesPPS->attachAxis(axisX_PPS);

    axisY_PPS = new QValueAxis();
    configAxisY(axisY_PPS, "#00e676", "%d");
    axisY_PPS->setRange(0, 1000);
    chartPPS->addAxis(axisY_PPS, Qt::AlignLeft);
    seriesPPS->attachAxis(axisY_PPS);

    viewPPS = new QChartView(chartPPS);
    viewPPS->setRenderHint(QPainter::Antialiasing);
    viewPPS->setStyleSheet("background: transparent;");

    // =========================================================
    // 2. 下半部分：Bandwidth 图表 (紫色)
    // =========================================================
    chartBW = new QChart();
    configChart(chartBW, "Bandwidth (MB/s)", "#d500f9");
    seriesMbps = new QSplineSeries();

    QPen penBW(QColor("#d500f9"));
    penBW.setWidth(2);
    seriesMbps->setPen(penBW);
    chartBW->addSeries(seriesMbps);

    axisX_BW = new QValueAxis();
    configAxisX(axisX_BW);
    chartBW->addAxis(axisX_BW, Qt::AlignBottom);
    seriesMbps->attachAxis(axisX_BW);

    axisY_BW = new QValueAxis();
    configAxisY(axisY_BW, "#d500f9", "%.1f");
    axisY_BW->setTitleText("MB/s");
    chartBW->addAxis(axisY_BW, Qt::AlignLeft); // 也是左对齐，但在下面的图里
    seriesMbps->attachAxis(axisY_BW);

    viewBW = new QChartView(chartBW);
    viewBW->setRenderHint(QPainter::Antialiasing);
    viewBW->setStyleSheet("background: transparent;");

    // =========================================================
    // 3. 添加到布局 (垂直排列)
    // =========================================================
    // 这里的 ui->grpChart 是我们在 UI 设计器里预留的 GroupBox
    QVBoxLayout *layout = new QVBoxLayout(ui->grpChart);
    layout->setContentsMargins(2, 10, 2, 2);
    layout->setSpacing(5); // 两个图表之间的间距

    layout->addWidget(viewPPS); // 上面放 PPS
    layout->addWidget(viewBW);  // 下面放 BW

    // 只有第一次需要设置伸缩因子，保证平分高度
    // 但在 QVBoxLayout 中默认就是平分的

    m_chartTimeX = 0;
    m_maxPPS = 100;
    m_maxMbps = 10;
}

void MainWindow::appendLog(const QString &msg, int level) {
    QString color = "#a0a8b7";
    QString prefix = "[INFO]";
    if (level == 1) { color = "#00e676"; prefix = "[OK]"; }
    else if (level == 2) { color = "#ff1744"; prefix = "[ERR]"; }
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString logHtml = QString("<span style='color:#555;'>[%1]</span> <span style='color:%2; font-weight:bold;'>%3</span> <span style='color:%2;'>%4</span>").arg(timestamp).arg(color).arg(prefix).arg(msg);
    ui->txtLog->append(logHtml);
    QScrollBar *sb = ui->txtLog->verticalScrollBar();
    sb->setValue(sb->maximum());
}

void MainWindow::loadInterfaces() {
    ui->comboInterfaceTx->clear();

    // [新增] 清空并初始化右侧 Socket 源列表
    // 注意：请确保你在 ui_sender.h 或 UI 文件中已经添加了 comboSockSrc
    if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
        ui->comboSockSrc->clear();
        ui->comboSockSrc->addItem("Auto (Let OS Decide)", ""); // 默认选项，对应 IP 为空
    }

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        ui->comboInterfaceTx->addItem("Error: " + QString(errbuf));
        appendLog(QString("Pcap Error: %1").arg(errbuf), 2);
        return;
    }

    for(pcap_if_t *d=alldevs; d; d=d->next) {
        QString pcapName = QString(d->name);
        QString desc = d->description ? QString(d->description) : pcapName;

        // 填充左侧 (WinPcap)
        ui->comboInterfaceTx->addItem(desc, pcapName);

        // [新增] 填充右侧 (Socket)
        // 我们存入 pcapName，在点击开始时再解析出 IP
        if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
            ui->comboSockSrc->addItem(desc, pcapName);
        }
    }
    pcap_freealldevs(alldevs);

    connect(ui->comboInterfaceTx, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::onInterfaceSelectionChanged);
    if (ui->comboInterfaceTx->count() > 0) {
        onInterfaceSelectionChanged(0);
    }
}

void MainWindow::onInterfaceSelectionChanged(int index) {
    QString pcapName = ui->comboInterfaceTx->itemData(index).toString();
    if (pcapName.isEmpty()) return;
    QString mac, ip;
    ui->editSrcMac->clear();
    ui->editSrcIp->clear();
    if (GetAdapterInfoWinAPI(pcapName, mac, ip)) {
        ui->editSrcMac->setText(mac);
        ui->editSrcIp->setText(ip);
        if (ip.isEmpty()) {
            ui->editSrcIp->setPlaceholderText("No IPv4 Assigned");
            appendLog("Interface selected. Warning: No IPv4 address found.", 0);
        } else {
            appendLog("Interface selected: " + ip, 0);
        }
    } else {
        ui->editSrcIp->setPlaceholderText("Info lookup failed");
        appendLog("Failed to fetch info for selected interface.", 2);
    }
}


void MainWindow::onGetDstMacClicked() {
#ifdef _WIN32
    QString dstIpStr = ui->editDstIp->currentText();
    if (dstIpStr.isEmpty()) {
        appendLog("Cannot resolve MAC: Destination IP is empty.", 2);
        QMessageBox::warning(this, "Input Error", "Please enter a Destination IP first.");
        return;
    }
    IPAddr DestIp = inet_addr(dstIpStr.toStdString().c_str());
    if (DestIp == INADDR_NONE) {
        appendLog("Cannot resolve MAC: Invalid IP address format.", 2);
        QMessageBox::warning(this, "Input Error", "Invalid IP Address format.");
        return;
    }
    ui->btnGetMac->setEnabled(false);
    ui->btnGetMac->setText("...");
    appendLog("Resolving MAC for " + dstIpStr + "...", 0);

    std::thread([this, DestIp, dstIpStr]() {
        ULONG MacAddr[2]; ULONG PhysAddrLen = 6; IPAddr SrcIp = 0;
        DWORD dwRet = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

        QMetaObject::invokeMethod(this, [this, dwRet, MacAddr, PhysAddrLen, dstIpStr]() {
            ui->btnGetMac->setEnabled(true);
            ui->btnGetMac->setText("GET");

            if (dwRet == NO_ERROR) {
                BYTE *bPhysAddr = (BYTE *) &MacAddr;
                QString macStr;
                if (PhysAddrLen) {
                    for (int i = 0; i < (int) PhysAddrLen; i++) {
                        if (i == (int) PhysAddrLen - 1) macStr += QString().asprintf("%.2X", (int) bPhysAddr[i]);
                        else macStr += QString().asprintf("%.2X:", (int) bPhysAddr[i]);
                    }
                }
                ui->editDstMac->setText(macStr);
                appendLog("MAC Resolved: " + macStr, 1);

                // 【新增】获取成功后，自动聚焦到 MAC 输入框，并全选方便复制或修改
                ui->editDstMac->setFocus();
                ui->editDstMac->selectAll();

            } else {
                QString errApi;
                if (dwRet == ERROR_GEN_FAILURE) errApi = "Generic Failure";
                else if (dwRet == ERROR_BAD_NET_NAME) errApi = "Bad Net Name";
                else if (dwRet == ERROR_NOT_FOUND) errApi = "Host Not Found (Timeout)";
                else errApi = QString::number(dwRet);
                appendLog("ARP Request Failed: " + errApi, 2);
                QMessageBox::warning(this, "ARP Failed", "Could not resolve MAC address.\nReason: " + errApi + "\nPlease ensure the target IP is online and in the same LAN.");
            }
        });
    }).detach();
#else
    appendLog("ARP feature is only available on Windows.", 2);
    QMessageBox::information(this, "Info", "ARP feature is currently Windows only.");
#endif
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

void MainWindow::onStartSendClicked() {
    if (workerThread && workerThread->isRunning()) return;
    saveHistory(ui->editDstIp->currentText());
    saveConfig();

    g_total_sent = 0;
    g_total_bytes = 0;
    lastTotalSent = 0;
    lastTotalBytes = 0;
    rateTimer.start();

    // [修改] 重置图表数据
    m_dashboard.updateUI(0, 0, 0, 0);

    seriesPPS->clear();
    seriesMbps->clear();
    m_rawByteHistory.clear(); // [新增] 清空原始数据历史

    m_chartTimeX = 0;
    m_maxPPS = 100;
    m_maxMbps = 10;

    axisX_PPS->setRange(0, 60);
    axisX_BW->setRange(0, 60);

    ui->btnStartSend->setEnabled(false);
    ui->btnStopSend->setEnabled(true);
    ui->comboInterfaceTx->setEnabled(false);
    ui->grpParam->setEnabled(false);
    ui->grpPayload->setEnabled(false);
    ui->grpAddr->setEnabled(false);
    appendLog("Starting transmission...", 1);

    if (workerThread) { delete worker; delete workerThread; }
    workerThread = new QThread(this);
    worker = new PacketWorker();
    memset(&worker->config, 0, sizeof(SenderConfig));
    std::string dev = ui->comboInterfaceTx->currentData().toString().toStdString();
    strncpy(worker->config.dev_name, dev.c_str(), sizeof(worker->config.dev_name) - 1);
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
    parseIp(ui->editDstIp->currentText(), worker->config.des_ip);
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
    worker->moveToThread(workerThread);
    connect(workerThread, &QThread::started, worker, &PacketWorker::doSendWork);
    connect(worker, &PacketWorker::workFinished, workerThread, &QThread::quit);
    connect(worker, &PacketWorker::statsUpdated, this, &MainWindow::updateStats, Qt::QueuedConnection);
    connect(workerThread, &QThread::finished, this, [this]() {
        ui->btnStartSend->setEnabled(true);
        ui->btnStopSend->setEnabled(false);
        ui->comboInterfaceTx->setEnabled(true);
        ui->grpParam->setEnabled(true);
        ui->grpPayload->setEnabled(true);
        ui->grpAddr->setEnabled(true);
        appendLog("Transmission thread stopped.", 0);
    });
    workerThread->start();
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


void MainWindow::onStopSendClicked() {
    // 1. 停止发送标志
    g_is_sending = false;
    ui->btnStopSend->setEnabled(false);

    // ==============================================================================
    // [修复核心] 不要在这里调用 updateStats！
    // updateStats 会重置 rateTimer，导致后续的排队信号计算出的时间间隔极小(1ms)，
    // 从而产生巨大的 PPS 尖峰 (Spike) 或者 0 值 (Dip)。
    // ==============================================================================

    // 2. 我们只更新底部的“数字”显示，确保显示的是最终的原子计数
    // 参数3和4传 0，表示停止时的瞬时速率为 0
    m_dashboard.updateUI(g_total_sent.load(), g_total_bytes.load(), 0, 0);

    // 3. 记录日志
    QString summary = QString("Stopped. Final Total: %1 packets, %2 bytes sent.")
                          .arg(g_total_sent.load())
                          .arg(g_total_bytes.load());
    appendLog(summary, 1); // 1 = Green/Success Color

    // 4. 清理动画效果
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

void MainWindow::updateStats(uint64_t currSent, uint64_t currBytes) {
    qint64 elapsedMs = rateTimer.restart();
    if (elapsedMs < 1) elapsedMs = 1;

    uint64_t diffSent = (currSent >= lastTotalSent) ? (currSent - lastTotalSent) : 0;
    uint64_t diffBytes = (currBytes >= lastTotalBytes) ? (currBytes - lastTotalBytes) : 0;

    lastTotalSent = currSent;
    lastTotalBytes = currBytes;

    // 1. 计算 PPS
    double pps = (double)diffSent * 1000.0 / elapsedMs;

    // 2. [修改] 计算 Bytes/sec (不再乘以 8)
    // 字节/毫秒 * 1000 = 字节/秒
    double currentBytesPerSec = (double)diffBytes * 1000.0 / elapsedMs;

    // 更新底部状态栏 (Dashboard 本身就是按 B/s 设计的，直接传即可)
    m_dashboard.updateUI(currSent, currBytes, pps, currentBytesPerSec);

    // =========================================================
    // 图表更新逻辑
    // =========================================================
    m_chartTimeX++;

    // --- 1. 更新 PPS 图表 ---
    seriesPPS->append(m_chartTimeX, pps);
    if (seriesPPS->count() > 60) seriesPPS->remove(0);

    if (pps > m_maxPPS) m_maxPPS = pps * 1.2;
    if (m_maxPPS < 100) m_maxPPS = 100;
    axisY_PPS->setRange(0, m_maxPPS);

    // --- 2. 更新 Bandwidth 图表 (Byte 单位自适应) ---

    // a. 存入历史 (Bytes)
    m_rawByteHistory.append(currentBytesPerSec);
    if (m_rawByteHistory.size() > 60) m_rawByteHistory.removeFirst();

    // b. 找出最大值
    double maxVal = 0;
    for (double v : m_rawByteHistory) {
        if (v > maxVal) maxVal = v;
    }

    // c. [修改] 决定单位 (使用 1024 进制)
    QString unitStr = "B/s";
    double divisor = 1.0;

    if (maxVal >= 1024.0 * 1024.0 * 1024.0) {
        unitStr = "GB/s";
        divisor = 1024.0 * 1024.0 * 1024.0;
    } else if (maxVal >= 1024.0 * 1024.0) {
        unitStr = "MB/s";
        divisor = 1024.0 * 1024.0;
    } else if (maxVal >= 1024.0) {
        unitStr = "KB/s";
        divisor = 1024.0;
    }

    // d. 重绘曲线
    QList<QPointF> points;
    qint64 startX = m_chartTimeX - m_rawByteHistory.size() + 1;

    for (int i = 0; i < m_rawByteHistory.size(); ++i) {
        points.append(QPointF(startX + i, m_rawByteHistory[i] / divisor));
    }
    seriesMbps->replace(points); // 替换所有点

    // e. 更新标题和量程
    chartBW->setTitle(QString("Bandwidth (%1)").arg(unitStr));
    axisY_BW->setTitleText(unitStr);

    double scaledMax = maxVal / divisor;
    if (scaledMax < 10.0) scaledMax = 10.0;

    axisY_BW->setRange(0, scaledMax * 1.2);

    // --- 3. 滚动 X 轴 ---
    if (m_chartTimeX > 60) {
        axisX_PPS->setRange(m_chartTimeX - 60, m_chartTimeX);
        axisX_BW->setRange(m_chartTimeX - 60, m_chartTimeX);
    } else {
        axisX_PPS->setRange(0, 60);
        axisX_BW->setRange(0, 60);
    }
}

// ============================================================================
// 加载配置 (启动时恢复界面状态)
// ============================================================================
void MainWindow::loadConfig() {
    QSettings settings("PacketStorm", "SenderConfig");

    // --- [原有] 左侧 WinPcap 模块配置加载 ---
    QString lastInterface = settings.value("config/interface_name").toString();
    int idx = ui->comboInterfaceTx->findData(lastInterface);
    if (idx != -1) {
        ui->comboInterfaceTx->setCurrentIndex(idx);
    } else {
        int savedIdx = settings.value("config/interface_index", 0).toInt();
        if(savedIdx >= 0 && savedIdx < ui->comboInterfaceTx->count())
            ui->comboInterfaceTx->setCurrentIndex(savedIdx);
    }
    ui->editSrcMac->setText(settings.value("config/src_mac", "").toString());
    ui->editDstMac->setText(settings.value("config/dst_mac", "").toString());
    ui->editSrcIp->setText(settings.value("config/src_ip", "").toString());
    QString currentDstIp = settings.value("config/dst_ip_val", "").toString();
    if(!currentDstIp.isEmpty()) ui->editDstIp->setEditText(currentDstIp);
    int proto = settings.value("config/protocol", 0).toInt();
    switch(proto) {
    case 0: ui->rbIcmp->setChecked(true); break;
    case 1: ui->rbUdp->setChecked(true); break;
    case 2: ui->rbTcp->setChecked(true); break;
    case 3: ui->rbDns->setChecked(true); break;
    }
    ui->chkSyn->setChecked(settings.value("config/tcp_syn", false).toBool());
    ui->chkAck->setChecked(settings.value("config/tcp_ack", false).toBool());
    ui->chkPsh->setChecked(settings.value("config/tcp_psh", false).toBool());
    ui->chkFin->setChecked(settings.value("config/tcp_fin", false).toBool());
    ui->chkRst->setChecked(settings.value("config/tcp_rst", false).toBool());
    int payMode = settings.value("config/payload_mode", 0).toInt();
    switch(payMode) {
    case 0: ui->rbPayRandom->setChecked(true); break;
    case 1: ui->rbPayFixed->setChecked(true); break;
    case 2: ui->rbPayCustom->setChecked(true); break;
    }
    ui->spinPktLen->setValue(settings.value("config/payload_len", 64).toInt());
    ui->spinFixVal->setValue(settings.value("config/fixed_val", 0).toInt());
    ui->editCustomData->setText(settings.value("config/custom_data", "").toString());
    ui->spinInterval->setValue(settings.value("config/interval", 10000).toInt());
    ui->spinSrcPort->setValue(settings.value("config/src_port", 10086).toInt());
    ui->spinDstPort->setValue(settings.value("config/dst_port", 10086).toInt());
    ui->editDomain->setText(settings.value("config/domain", "www.google.com").toString());

    // ========================================================================
    // [新增] 右侧 OS Stack Sender 配置加载
    // ========================================================================

    // 1. Source Interface (下拉框)
    // 此时 loadInterfaces() 已经执行完毕，下拉框已有数据
    QString sockIface = settings.value("sock_config/source_iface", "").toString();
    if (!sockIface.isEmpty()) {
        int sockIdx = ui->comboSockSrc->findData(sockIface);
        if (sockIdx != -1) {
            ui->comboSockSrc->setCurrentIndex(sockIdx);
        }
    }

    // 2. Target IP
    QString savedSockIp = settings.value("sock_config/target_ip", "192.168.1.1").toString();
    if (!savedSockIp.isEmpty()) {
        ui->editSockIp->setText(savedSockIp);
    }

    // 3. Target Port
    ui->spinSockPort->setValue(settings.value("sock_config/target_port", 8080).toInt());

    // 4. Protocol (UDP/TCP)
    bool isSockUdp = settings.value("sock_config/is_udp", true).toBool();
    if (isSockUdp) ui->rbSockUdp->setChecked(true);
    else ui->rbSockTcp->setChecked(true);

    // 5. Payload Size
    ui->spinSockLen->setValue(settings.value("sock_config/payload_len", 60000).toInt());

    // 6. Interval
    ui->spinSockInt->setValue(settings.value("sock_config/interval", 1000).toInt());
}

// ============================================================================
// 保存配置 (关闭窗口或点击开始发送时调用)
// ============================================================================
void MainWindow::saveConfig() {
    QSettings settings("PacketStorm", "SenderConfig");

    // --- [原有] 左侧 WinPcap 模块配置保存 ---
    settings.setValue("config/interface_name", ui->comboInterfaceTx->currentData().toString());
    settings.setValue("config/interface_index", ui->comboInterfaceTx->currentIndex());
    settings.setValue("config/src_mac", ui->editSrcMac->text());
    settings.setValue("config/dst_mac", ui->editDstMac->text());
    settings.setValue("config/src_ip", ui->editSrcIp->text());
    settings.setValue("config/dst_ip_val", ui->editDstIp->currentText());
    int proto = 0;
    if(ui->rbUdp->isChecked()) proto = 1;
    else if(ui->rbTcp->isChecked()) proto = 2;
    else if(ui->rbDns->isChecked()) proto = 3;
    settings.setValue("config/protocol", proto);
    settings.setValue("config/tcp_syn", ui->chkSyn->isChecked());
    settings.setValue("config/tcp_ack", ui->chkAck->isChecked());
    settings.setValue("config/tcp_psh", ui->chkPsh->isChecked());
    settings.setValue("config/tcp_fin", ui->chkFin->isChecked());
    settings.setValue("config/tcp_rst", ui->chkRst->isChecked());
    int payMode = 0;
    if(ui->rbPayFixed->isChecked()) payMode = 1;
    else if(ui->rbPayCustom->isChecked()) payMode = 2;
    settings.setValue("config/payload_mode", payMode);
    settings.setValue("config/payload_len", ui->spinPktLen->value());
    settings.setValue("config/fixed_val", ui->spinFixVal->value());
    settings.setValue("config/custom_data", ui->editCustomData->text());
    settings.setValue("config/interval", ui->spinInterval->value());
    settings.setValue("config/src_port", ui->spinSrcPort->value());
    settings.setValue("config/dst_port", ui->spinDstPort->value());
    settings.setValue("config/domain", ui->editDomain->text());

    // ========================================================================
    // [新增] 右侧 OS Stack Sender 配置保存
    // ========================================================================

    // 1. Source Interface (保存 Pcap Device Name，即 itemData)
    settings.setValue("sock_config/source_iface", ui->comboSockSrc->currentData().toString());

    // 2. Target IP
    settings.setValue("sock_config/target_ip", ui->editSockIp->text());

    // 3. Target Port
    settings.setValue("sock_config/target_port", ui->spinSockPort->value());

    // 4. Protocol
    settings.setValue("sock_config/is_udp", ui->rbSockUdp->isChecked());

    // 5. Payload Size
    settings.setValue("sock_config/payload_len", ui->spinSockLen->value());

    // 6. Interval
    settings.setValue("sock_config/interval", ui->spinSockInt->value());
}

// ============================================================================
// 加载历史记录 (启动时调用)
// ============================================================================
void MainWindow::loadHistory() {
    QSettings settings("PacketStorm", "SenderConfig");

    // 读取保存的列表
    QStringList history = settings.value("history/dst_ip").toStringList();

    ui->editDstIp->clear();
    if (!history.isEmpty()) {
        ui->editDstIp->addItems(history);
        // 默认选中最近的一个
        ui->editDstIp->setCurrentIndex(0);
    } else {
        // 如果没有历史，给个默认值
        ui->editDstIp->setEditText("192.168.1.1");
    }
}

// ============================================================================
// 保存历史记录 (点击发送时调用)
// ============================================================================
void MainWindow::saveHistory(const QString &ip) {
    if (ip.isEmpty()) return;

    QSettings settings("PacketStorm", "SenderConfig");
    QStringList history = settings.value("history/dst_ip").toStringList();

    // 1. 去重：移除已存在的相同项，并移除空项
    history.removeAll(ip);
    history.removeAll("");

    // 2. 插入：将当前 IP 插入到最前面 (最近使用的排第一)
    history.insert(0, ip);

    // 3. 限制：只保留最近 10 条
    while (history.size() > 10) {
        history.removeLast();
    }

    // 4. 保存回磁盘
    settings.setValue("history/dst_ip", history);

    // 5. 刷新 UI 下拉列表（保持当前输入框内容不变）
    ui->editDstIp->blockSignals(true); // 暂停信号，防止触发 currentIndexChanged
    ui->editDstIp->clear();
    ui->editDstIp->addItems(history);
    ui->editDstIp->setEditText(ip);    // 恢复当前显示的文本
    ui->editDstIp->blockSignals(false);
}
