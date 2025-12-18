#include "sender_window.h"
#include "ui_sender.h"
#include <QDateTime>
#include <QDebug>
#include <QGraphicsLayout>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <functional>
#include <pcap.h>
#include <thread>

// ============================================================================
// Windows API 头文件与库链接
// ============================================================================
#ifdef _WIN32
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
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
    int valueFromText(const QString& text) const override {
        QString t = text;
        t.remove(',');
        return t.toInt();
    }
    QString textFromValue(int val) const override { return locale().toString(val); }
    QValidator::State validate(QString& text, int& pos) const override {
        int digitsBefore = 0;
        for (int i = 0; i < pos; ++i)
            if (text[i].isDigit()) digitsBefore++;
        QString raw = text;
        static const QRegularExpression regex("[^0-9]");
        raw.remove(regex);
        if (raw.isEmpty()) return QValidator::Intermediate;
        QString formatted = locale().toString(raw.toLongLong());
        if (text != formatted) {
            text = formatted;
            int newPos = 0;
            int digitsSeen = 0;
            while (newPos < text.length() && digitsSeen < digitsBefore) {
                if (text[newPos].isDigit()) digitsSeen++;
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
                                 .arg(pAdapter->Address[5], 2, 16, QChar('0'))
                                 .toUpper();
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

// 在 sender_window.cpp 中 GetAdapterInfoWinAPI 之后添加
static bool GetExtendedNetworkInfo(const QString& srcIp, QString& outMask, QString& outGateway) {
#ifdef _WIN32
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
            // 遍历该网卡下的所有 IP 地址，寻找与 srcIp 匹配的
            PIP_ADDR_STRING pIpStr = &pAdapter->IpAddressList;
            while (pIpStr) {
                if (QString(pIpStr->IpAddress.String) == srcIp) {
                    outMask = QString(pIpStr->IpMask.String);
                    outGateway = QString(pAdapter->GatewayList.IpAddress.String);
                    found = true;
                    break;
                }
                pIpStr = pIpStr->Next;
            }
            if (found) break;
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
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), workerThread(nullptr), worker(nullptr), stopBtnAnim(nullptr),
      stopBtnEffect(nullptr), sockThread(nullptr), sockWorker(nullptr) {
    ui->setupUi(this);
    setupHexTableStyle();

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
    appendLog("System initialized. Scanning interfaces...", 0);

    loadInterfaces();

    // 2. 验证器
    QRegularExpression ipRegex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}("
                               "25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    QRegularExpressionValidator* ipVal = new QRegularExpressionValidator(ipRegex, this);
    ui->editSrcIp->setValidator(ipVal);
    if (ui->editDstIp->lineEdit()) {
        ui->editDstIp->lineEdit()->setValidator(ipVal);
    }

    // [新增] 为右侧 Socket 模块的 IP 输入框添加验证器
    ui->editSockIp->setValidator(new QRegularExpressionValidator(ipRegex, this));

    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    QRegularExpressionValidator* macVal = new QRegularExpressionValidator(macRegex, this);
    ui->editSrcMac->setValidator(macVal);
    ui->editDstMac->setValidator(macVal);

    ui->editSrcMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");
    ui->editDstMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");

    // 3. 状态栏
    QStatusBar* bar = new QStatusBar(this);
    setStatusBar(bar);
    m_dashboard.init(bar, this);

    // 4. PPS 标签
    lblTargetPPS = new QLabel("Rate: -- pps", this);
    lblTargetPPS->setStyleSheet("color: #FFB74D; font-size: 11px;");
    ui->formLayout_Param->addRow("", lblTargetPPS);

    // 5. 信号连接
    connect(ui->spinInterval, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int intervalUs) {
        if (intervalUs <= 0) {
            lblTargetPPS->setText("Target: Max Speed");
        } else {
            double pps = 1000000.0 / (double)intervalUs;
            QString ppsText;
            if (pps >= 1000000)
                ppsText = QString::number(pps / 1000000.0, 'f', 2) + " Mpps";
            else if (pps >= 1000)
                ppsText = QString::number(pps / 1000.0, 'f', 1) + " kpps";
            else
                ppsText = QString::number((int)pps) + " pps";
            lblTargetPPS->setText("Target: " + ppsText);
        }
    });

    connect(ui->btnStartSend, &QPushButton::clicked, this, &MainWindow::onStartSendClicked);
    connect(ui->btnStopSend, &QPushButton::clicked, this, &MainWindow::onStopSendClicked);
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);

    // [新增] 连接 ARP RadioButton 的信号
    connect(ui->rbArp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);

    connect(ui->rbPayRandom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayFixed, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayCustom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->btnGetMac, &QPushButton::clicked, this, &MainWindow::onGetDstMacClicked);

    // [新增] 连接右侧 Socket 发送模块的信号
    connect(ui->btnSockStart, &QPushButton::clicked, this, &MainWindow::onSockStartClicked);
    connect(ui->btnSockStop, &QPushButton::clicked, this, &MainWindow::onSockStopClicked);

    connect(ui->editCustomData, &QLineEdit::textChanged, this, [this](const QString& text) {
        if (ui->rbPayCustom->isChecked()) {
            ui->spinPktLen->setValue(text.toUtf8().length());
        }
    });

    setupChart();
    loadHistory();
    loadConfig();

    onProtoToggled();
    onPayloadModeChanged();
    emit ui->spinInterval->valueChanged(ui->spinInterval->value());
    setupTrafficTable();
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
    strncpy(sockWorker->config.target_ip, ip.c_str(), sizeof(sockWorker->config.target_ip) - 1);

    memset(sockWorker->config.source_ip, 0, sizeof(sockWorker->config.source_ip));
    if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
        QString selectedPcapName = ui->comboSockSrc->currentData().toString();
        if (selectedPcapName.isEmpty()) {
            strcpy(sockWorker->config.source_ip, "0.0.0.0");
            appendLog("[SOCK] Routing: Auto (Default)", 0);
        } else {
            QString mac, srcIp;
            if (GetAdapterInfoWinAPI(selectedPcapName, mac, srcIp) && !srcIp.isEmpty() && srcIp != "0.0.0.0") {
                strncpy(sockWorker->config.source_ip, srcIp.toStdString().c_str(),
                        sizeof(sockWorker->config.source_ip) - 1);
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
    connect(
        sockWorker, &SocketWorker::logUpdated, this, [this](QString msg, int level) { this->appendLog(msg, level); },
        Qt::QueuedConnection);

    // === [关键修复] 线程结束后的清理逻辑 ===
    connect(sockThread, &QThread::finished, this, [this]() {
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
    QVBoxLayout* layout = new QVBoxLayout(ui->grpChart);
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

void MainWindow::loadInterfaces() {
    ui->comboInterfaceTx->clear();

    // [新增] 清空并初始化右侧 Socket 源列表
    // 注意：请确保你在 ui_sender.h 或 UI 文件中已经添加了 comboSockSrc
    if (ui->centralwidget->findChild<QComboBox*>("comboSockSrc")) {
        ui->comboSockSrc->clear();
        ui->comboSockSrc->addItem("Auto (Let OS Decide)",
                                  ""); // 默认选项，对应 IP 为空
    }

    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        ui->comboInterfaceTx->addItem("Error: " + QString(errbuf));
        appendLog(QString("Pcap Error: %1").arg(errbuf), 2);
        return;
    }

    for (pcap_if_t* d = alldevs; d; d = d->next) {
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

    connect(ui->comboInterfaceTx, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onInterfaceSelectionChanged);
    // 不在这里自动选择第一个网口，让 loadConfig() 来决定选择哪个网口
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
        QString interfaceName = ui->comboInterfaceTx->itemText(index);
        appendLog("Failed to fetch info for selected interface: " + interfaceName, 2);
    }
    // 保存当前选择的网口
    saveConfig();
}
void MainWindow::onGetDstMacClicked() {
#ifdef _WIN32
    QString dstIpStr = ui->editDstIp->currentText();
    QString srcIpStr = ui->editSrcIp->text(); // 获取源 IP

    if (dstIpStr.isEmpty()) {
        appendLog("Cannot resolve MAC: Destination IP is empty.", 2);
        QMessageBox::warning(this, "Input Error", "Please enter a Destination IP first.");
        return;
    }

    // 1. 准备 IP 地址结构
    IPAddr DestIp = inet_addr(dstIpStr.toStdString().c_str());
    IPAddr SrcIpAddr = inet_addr(srcIpStr.toStdString().c_str());

    if (DestIp == INADDR_NONE) {
        appendLog("Cannot resolve MAC: Invalid IP address format.", 2);
        QMessageBox::warning(this, "Input Error", "Invalid IP Address format.");
        return;
    }

    // 2. [核心逻辑] 判断是否跨网段
    QString maskStr, gatewayStr;
    bool isRemote = false;
    QString actualArpTargetStr = dstIpStr; // 默认解析目标 IP
    IPAddr FinalArpTarget = DestIp;        // 默认解析目标 IP

    // 获取掩码和网关
    if (GetExtendedNetworkInfo(srcIpStr, maskStr, gatewayStr)) {
        IPAddr Mask = inet_addr(maskStr.toStdString().c_str());

        // 子网计算：(Src & Mask) vs (Dst & Mask)
        if ((SrcIpAddr & Mask) != (DestIp & Mask)) {
            // 跨网段：检查网关是否存在
            if (!gatewayStr.isEmpty() && gatewayStr != "0.0.0.0") {
                isRemote = true;
                actualArpTargetStr = gatewayStr;
                FinalArpTarget = inet_addr(gatewayStr.toStdString().c_str());
                appendLog(QString("Target %1 is remote. Resolving Gateway: %2").arg(dstIpStr).arg(gatewayStr), 0);
            } else {
                appendLog("Target is remote but no Gateway found. Trying direct ARP...", 0);
            }
        } else {
            appendLog("Target is in local subnet.", 0);
        }
    }

    // 3. UI 交互锁定
    ui->btnGetMac->setEnabled(false);
    ui->btnGetMac->setText("...");
    appendLog("Resolving MAC for " + actualArpTargetStr + "...", 0);

    // 4. 启动线程发送 ARP
    // 注意：这里 lambda 捕获了 FinalArpTarget (即网关IP或目标IP)
    std::thread([this, FinalArpTarget, actualArpTargetStr]() {
        ULONG MacAddr[2];
        memset(MacAddr, 0xff, sizeof(MacAddr));
        ULONG PhysAddrLen = 6;
        IPAddr SrcIp = 0; // 让系统自动选择源接口，或者传入 SrcIpAddr

        // 发送 ARP 请求
        DWORD dwRet = SendARP(FinalArpTarget, SrcIp, &MacAddr, &PhysAddrLen);

        QMetaObject::invokeMethod(this, [this, dwRet, MacAddr, PhysAddrLen, actualArpTargetStr]() {
            ui->btnGetMac->setEnabled(true);
            ui->btnGetMac->setText("GET");

            if (dwRet == NO_ERROR) {
                BYTE* bPhysAddr = (BYTE*)&MacAddr;
                QString macStr;
                if (PhysAddrLen) {
                    for (int i = 0; i < (int)PhysAddrLen; i++) {
                        if (i == (int)PhysAddrLen - 1)
                            macStr += QString().asprintf("%.2X", (int)bPhysAddr[i]);
                        else
                            macStr += QString().asprintf("%.2X:", (int)bPhysAddr[i]);
                    }
                }
                ui->editDstMac->setText(macStr);

                // 提示用户解析的是哪个 IP 的 MAC
                appendLog("MAC Resolved (" + actualArpTargetStr + "): " + macStr, 1);

                ui->editDstMac->setFocus();
                ui->editDstMac->selectAll();

            } else {
                QString errApi;
                if (dwRet == ERROR_GEN_FAILURE)
                    errApi = "Generic Failure";
                else if (dwRet == ERROR_BAD_NET_NAME)
                    errApi = "Bad Net Name";
                else if (dwRet == ERROR_NOT_FOUND)
                    errApi = "Host Not Found (Timeout)";
                else
                    errApi = QString::number(dwRet);
                appendLog("ARP Request Failed: " + errApi, 2);
                QMessageBox::warning(
                    this, "ARP Failed",
                    "Could not resolve MAC address.\nTarget: " + actualArpTargetStr + "\nReason: " + errApi);
            }
        });
    }).detach();
#else
    appendLog("ARP feature is only available on Windows.", 2);
    QMessageBox::information(this, "Info", "ARP feature is currently Windows only.");
#endif
}

void MainWindow::onPayloadModeChanged() {
    bool isFixed = ui->rbPayFixed->isChecked();
    bool isCustom = ui->rbPayCustom->isChecked();
    ui->lblFixVal->setVisible(isFixed);
    ui->spinFixVal->setVisible(isFixed);
    ui->editCustomData->setVisible(isCustom);
    if (isCustom) {
        ui->spinPktLen->setReadOnly(true);
        ui->spinPktLen->setStyleSheet("background-color: #1a202c; color: #718096; "
                                      "border: 1px dashed #2d3748;");
        ui->spinPktLen->setValue(ui->editCustomData->text().toUtf8().length());
    } else {
        ui->spinPktLen->setReadOnly(false);
        ui->spinPktLen->setStyleSheet("");
    }
}

// 在 sender_window.cpp 中找到 onProtoToggled 函数
void MainWindow::onProtoToggled() {
    bool isUdp = ui->rbUdp->isChecked();
    bool isTcp = ui->rbTcp->isChecked();
    bool isIcmp = ui->rbIcmp->isChecked();
    bool isDns = ui->rbDns->isChecked();
    bool isArp = ui->rbArp->isChecked(); // [新增]

    // ARP 也不需要载荷设置 (ARP 是固定结构)
    bool showPayloadOpts = isUdp || isTcp || isIcmp;

    // 端口只针对 TCP/UDP
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

    // 所有协议都允许设置发包间隔
    ui->lblIntVal->setVisible(true);
    ui->spinInterval->setVisible(true);

    if (isArp) {
        ui->spinPktLen->setEnabled(false); // ARP 长度固定
        // 提示用户：广播 ARP 请将 DstMAC 设为 FF:FF...
        if (ui->editDstMac->text().isEmpty()) {
            ui->editDstMac->setText("FF:FF:FF:FF:FF:FF");
        }
    } else {
        ui->spinPktLen->setEnabled(true);
    }
}

// ============================================================================
// Wireshark 风格辅助函数
// ============================================================================

// 1. 初始化表格列宽与信号连接
void MainWindow::setupTrafficTable() {
    // 1. 设置列头
    QStringList headers;
    headers << "No." << "Time" << "Source" << "Destination" << "Proto" << "Len"
            << "Info";
    ui->tablePackets->setColumnCount(7);
    ui->tablePackets->setHorizontalHeaderLabels(headers);

    // 2. 样式表设置 (保持不变)
    ui->tablePackets->setStyleSheet("QTableWidget {"
                                    "   background-color: #050505;"
                                    "   color: #a0a8b7;"
                                    "   gridline-color: #1c2333;"
                                    "   border: none;"
                                    "   font-family: 'JetBrains Mono';"
                                    "   font-size: 10px;"
                                    "}"
                                    "QHeaderView::section {"
                                    "   background-color: #0f121a;"
                                    "   color: #00e676;"
                                    "   padding: 2px;"
                                    "   border: 1px solid #1c2333;"
                                    "   font-size: 10px;"
                                    "   height: 18px;"
                                    "}"
                                    "QTableWidget::item {"
                                    "   padding-top: 0px;"
                                    "   padding-bottom: 0px;"
                                    "   border: none;"
                                    "}"
                                    "QTableWidget::item:selected {"
                                    "   background-color: #00e676;"
                                    "   color: #000000;"
                                    "}");

    // 3. 基础属性
    ui->tablePackets->verticalHeader()->setVisible(false);
    ui->tablePackets->verticalHeader()->setDefaultSectionSize(18);
    ui->tablePackets->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // =========================================================
    // [修复] 启用水平滚动条的关键设置
    // =========================================================

    // 1. 强制显示滚动条策略
    ui->tablePackets->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    // 2. 交互模式：允许用户拖拽列宽，允许列宽超出视口
    ui->tablePackets->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

    // [关键修改] 必须设为 false！否则最后一列会永远收缩以适应窗口，导致不出滚动条
    ui->tablePackets->horizontalHeader()->setStretchLastSection(false);

    // 3. 设置初始列宽
    // 给每一列足够的宽度，总宽度加起来要超过 Splitter
    // 分给它的区域，滚动条才会出现
    ui->tablePackets->setColumnWidth(0, 60);  // No.
    ui->tablePackets->setColumnWidth(1, 110); // Time
    ui->tablePackets->setColumnWidth(2, 140); // Source (宽一点显示完整IP)
    ui->tablePackets->setColumnWidth(3, 140); // Destination
    ui->tablePackets->setColumnWidth(4, 60);  // Proto
    ui->tablePackets->setColumnWidth(5, 50);  // Len

    // [关键修改] 给 Info 列一个固定的、足够宽的宽度
    ui->tablePackets->setColumnWidth(6, 400); // Info

    // =========================================================

    // 4. 选择模式配置
    ui->tablePackets->setShowGrid(false);
    ui->tablePackets->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tablePackets->setSelectionMode(QAbstractItemView::SingleSelection);

    // 5. 信号连接
    ui->tablePackets->disconnect();

    connect(ui->tablePackets, &QTableWidget::itemSelectionChanged, this, [this]() {
        auto items = ui->tablePackets->selectedItems();
        if (items.isEmpty()) return;
        int row = items.first()->row();
        QTableWidgetItem* dataItem = ui->tablePackets->item(row, 0);
        if (dataItem) {
            QByteArray data = dataItem->data(Qt::UserRole).toByteArray();
            updateHexTable(data);
        }
        if (ui->tablePackets->hasFocus()) {
            ui->chkAutoScroll->setChecked(false);
        }
    });
}

MainWindow::PacketInfo MainWindow::parsePacket(const QByteArray& data) {
    PacketInfo info; // 这里指的是 MainWindow::PacketInfo
    info.length = data.size();
    info.proto = "ETH";
    info.info = "Raw Ethernet Frame";

    if (data.size() < 14) return info;

    const unsigned char* bytes = (const unsigned char*)data.constData();

    // 辅助 Lambda: 格式化 MAC
    auto fmtMac = [](const unsigned char* b) {
        return QString("%1:%2:%3:%4:%5:%6")
            .arg(b[0], 2, 16, QChar('0'))
            .arg(b[1], 2, 16, QChar('0'))
            .arg(b[2], 2, 16, QChar('0'))
            .arg(b[3], 2, 16, QChar('0'))
            .arg(b[4], 2, 16, QChar('0'))
            .arg(b[5], 2, 16, QChar('0'))
            .toUpper();
    };

    // Ethernet Header
    uint16_t ethType = (bytes[12] << 8) | bytes[13];

    // ARP (0x0806)
    if (ethType == 0x0806) {
        info.proto = "ARP";
        info.src = fmtMac(bytes + 6); // Source MAC from Eth Header
        info.dst = fmtMac(bytes + 0); // Dest MAC from Eth Header

        if (data.size() >= 42) {
            uint16_t oper = (bytes[20] << 8) | bytes[21];
            // 提取 Sender IP 和 Target IP
            QString spa = QString("%1.%2.%3.%4").arg(bytes[28]).arg(bytes[29]).arg(bytes[30]).arg(bytes[31]);
            QString tpa = QString("%1.%2.%3.%4").arg(bytes[38]).arg(bytes[39]).arg(bytes[40]).arg(bytes[41]);

            if (oper == 1)
                info.info = QString("Who has %1? Tell %2").arg(tpa).arg(spa);
            else if (oper == 2)
                info.info = QString("%1 is at %2").arg(spa).arg(fmtMac(bytes + 22));
            else
                info.info = "Unknown Operation";
        }
    }
    // IPv4 (0x0800)
    else if (ethType == 0x0800) {
        if (data.size() < 34) {
            info.info = "IPv4 (Truncated)";
            return info;
        }

        uint8_t protocol = bytes[23];
        uint8_t srcIp[4], dstIp[4];
        memcpy(srcIp, bytes + 26, 4);
        memcpy(dstIp, bytes + 30, 4);

        info.src = QString("%1.%2.%3.%4").arg(srcIp[0]).arg(srcIp[1]).arg(srcIp[2]).arg(srcIp[3]);
        info.dst = QString("%1.%2.%3.%4").arg(dstIp[0]).arg(dstIp[1]).arg(dstIp[2]).arg(dstIp[3]);

        // Protocol Analysis
        if (protocol == 1) { // ICMP
            info.proto = "ICMP";
            if (data.size() > 34) {
                uint8_t type = bytes[34];
                uint16_t seq = (bytes[38] << 8) | bytes[39];
                if (type == 8)
                    info.info = QString("Echo (ping) request  id=0x%1 seq=%2")
                                    .arg((bytes[36] << 8) | bytes[37], 0, 16)
                                    .arg(seq);
                else if (type == 0)
                    info.info = QString("Echo (ping) reply    id=0x%1 seq=%2")
                                    .arg((bytes[36] << 8) | bytes[37], 0, 16)
                                    .arg(seq);
                else
                    info.info = QString("Type: %1").arg(type);
            }
        } else if (protocol == 6) { // TCP
            info.proto = "TCP";
            if (data.size() > 54) {
                uint16_t srcPort = (bytes[34] << 8) | bytes[35];
                uint16_t dstPort = (bytes[36] << 8) | bytes[37];
                uint8_t flags = bytes[47];
                QString flagStr;
                if (flags & 0x02) flagStr += "SYN ";
                if (flags & 0x10) flagStr += "ACK ";
                if (flags & 0x08) flagStr += "PSH ";
                if (flags & 0x01) flagStr += "FIN ";
                if (flags & 0x04) flagStr += "RST ";
                info.info = QString("%1 -> %2 [%3] Len=%4")
                                .arg(srcPort)
                                .arg(dstPort)
                                .arg(flagStr.trimmed())
                                .arg(info.length - 54);
            }
        } else if (protocol == 17) { // UDP
            info.proto = "UDP";
            if (data.size() > 42) {
                uint16_t srcPort = (bytes[34] << 8) | bytes[35];
                uint16_t dstPort = (bytes[36] << 8) | bytes[37];

                if (dstPort == 53 || srcPort == 53) {
                    info.proto = "DNS";
                    info.info = "Standard Query";
                } else {
                    info.info = QString("%1 -> %2  Len=%3").arg(srcPort).arg(dstPort).arg(info.length - 42);
                }
            }
        } else {
            info.proto = "IPv4";
            info.info = QString("Proto ID: %1").arg(protocol);
        }
    } else {
        // Unknown Ethernet Type
        info.proto = QString("0x%1").arg(ethType, 4, 16, QChar('0'));
        info.src = fmtMac(bytes + 6);
        info.dst = fmtMac(bytes + 0);
        info.info = "Ethernet II Frame";
    }

    return info;
}

void MainWindow::onStartSendClicked() {
    // 1. 防止重复启动
    if (workerThread && workerThread->isRunning()) return;

    // 2. 保存历史与配置
    saveHistory(ui->editDstIp->currentText());
    saveConfig();

    // 3. 重置全局统计
    g_total_sent = 0;
    g_total_bytes = 0;
    lastTotalSent = 0;
    lastTotalBytes = 0;
    rateTimer.start();

    // 4. 重置 Dashboard 和图表
    m_dashboard.updateUI(0, 0, 0, 0);
    seriesPPS->clear();
    seriesMbps->clear();
    m_ppsHistory.clear();
    m_rawByteHistory.clear();
    m_chartTimeX = 0;
    axisX_PPS->setRange(0, 60);
    axisX_BW->setRange(0, 60);

    // ========================================================================
    // [UI Reset] Wireshark 风格列表初始化
    // ========================================================================
    // if (ui->txtLog) ui->txtLog->clear();          // 1. 清空左侧日志
    ui->tablePackets->setRowCount(0); // 2. 清空中间表格

    m_packetCount = 0;
    setupTrafficTable();
    ui->tablePackets->verticalHeader()->setMinimumSectionSize(15);
    // ========================================================================

    // 5. 锁定 UI
    ui->btnStartSend->setEnabled(false);
    ui->btnStopSend->setEnabled(true);
    ui->comboInterfaceTx->setEnabled(false);
    ui->grpParam->setEnabled(false);
    ui->grpPayload->setEnabled(false);
    ui->grpAddr->setEnabled(false);

    // 6. 准备工作线程
    if (workerThread) {
        delete worker;
        delete workerThread;
    }
    workerThread = new QThread(this);
    worker = new PacketWorker();
    memset(&worker->config, 0, sizeof(SenderConfig));

    // 7. 填充配置 (MAC, IP, Interface)
    std::string dev = ui->comboInterfaceTx->currentData().toString().toStdString();
    strncpy(worker->config.dev_name, dev.c_str(), sizeof(worker->config.dev_name) - 1);

    auto parseMac = [](QString s, unsigned char* buf) {
        static const QRegularExpression regex("[:-]");
        QStringList p = s.split(regex);
        for (int i = 0; i < 6 && i < p.size(); ++i) buf[i] = p[i].toUInt(nullptr, 16);
    };
    auto parseIp = [](QString s, unsigned char* buf) {
        QStringList p = s.split('.');
        for (int i = 0; i < 4 && i < p.size(); ++i) buf[i] = p[i].toUInt();
    };

    parseMac(ui->editSrcMac->text(), worker->config.src_mac);
    parseMac(ui->editDstMac->text(), worker->config.des_mac);
    parseIp(ui->editSrcIp->text(), worker->config.src_ip);
    parseIp(ui->editDstIp->currentText(), worker->config.des_ip);

    // 8. 填充参数
    worker->config.send_interval_us = ui->spinInterval->value();
    worker->config.src_port = ui->spinSrcPort->value();
    worker->config.dst_port = ui->spinDstPort->value();

    if (ui->rbUdp->isChecked())
        worker->config.packet_type = UDP_PACKAGE;
    else if (ui->rbTcp->isChecked())
        worker->config.packet_type = TCP_PACKAGE;
    else if (ui->rbDns->isChecked())
        worker->config.packet_type = DNS_PACKAGE;
    else if (ui->rbArp->isChecked())
        worker->config.packet_type = ARP_PACKAGE;
    else
        worker->config.packet_type = ICMP_PACKAGE;

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

    // 9. 载荷配置
    worker->config.payload_len = ui->spinPktLen->value();
    if (ui->rbPayFixed->isChecked()) {
        worker->config.payload_mode = PAYLOAD_FIXED;
        worker->config.fixed_byte_val = (unsigned char)ui->spinFixVal->value();
    } else if (ui->rbPayCustom->isChecked()) {
        worker->config.payload_mode = PAYLOAD_CUSTOM;
        worker->customDataBuffer = ui->editCustomData->text().toUtf8();
    } else {
        worker->config.payload_mode = PAYLOAD_RANDOM;
    }

    // 10. 线程与信号连接
    worker->moveToThread(workerThread);

    connect(workerThread, &QThread::started, worker, &PacketWorker::doSendWork);
    connect(worker, &PacketWorker::workFinished, workerThread, &QThread::quit);
    connect(worker, &PacketWorker::statsUpdated, this, &MainWindow::updateStats, Qt::QueuedConnection);

    // ========================================================================
    // [核心] Wireshark 风格数据流更新逻辑
    // ========================================================================
    connect(
        worker, &PacketWorker::hexUpdated, this,
        [this](QByteArray data) {
            // 1. 数据解析
            m_packetCount++;
            // 调用成员函数 parsePacket
            PacketInfo info = parsePacket(data);

            // 2. 限制行数 (防止内存溢出，保留最近 1000 条)
            if (ui->tablePackets->rowCount() > 1000) {
                ui->tablePackets->removeRow(0);
            }

            // 3. 插入新行
            int row = ui->tablePackets->rowCount();
            ui->tablePackets->insertRow(row);

            // 4. 设置单元格内容
            // 辅助函数：创建 Item 并设置对齐
            auto createItem = [](QString txt, bool center = false) {
                QTableWidgetItem* it = new QTableWidgetItem(txt);
                if (center) it->setTextAlignment(Qt::AlignCenter);
                return it;
            };

            QTableWidgetItem* numItem = createItem(QString::number(m_packetCount), true);

            ui->tablePackets->setItem(row, 0, numItem);
            ui->tablePackets->setItem(row, 1, createItem(QDateTime::currentDateTime().toString("HH:mm:ss.zzz")));
            ui->tablePackets->setItem(row, 2, createItem(info.src));
            ui->tablePackets->setItem(row, 3, createItem(info.dst));
            ui->tablePackets->setItem(row, 4, createItem(info.proto, true));
            ui->tablePackets->setItem(row, 5, createItem(QString::number(info.length), true));
            ui->tablePackets->setItem(row, 6, createItem(info.info));

            // 5. [关键] 将原始二进制数据绑定到第 0 列 (No. 列)
            // 这样点击这一行时，我们可以取出数据并显示在下方 Hex 视图中
            numItem->setData(Qt::UserRole, data);

            // 6. 自动滚动与视图联动
            if (ui->chkAutoScroll->isChecked()) {
                ui->tablePackets->scrollToBottom();

                // [修复] 自动滚动时，实时显示最新包的 Hex
                updateHexTable(data);
            }
        },
        Qt::QueuedConnection);
    // ========================================================================

    // 11. 结束清理
    connect(workerThread, &QThread::finished, this, [this]() {
        ui->btnStartSend->setEnabled(true);
        ui->btnStopSend->setEnabled(false);
        ui->comboInterfaceTx->setEnabled(true);
        ui->grpParam->setEnabled(true);
        ui->grpPayload->setEnabled(true);
        ui->grpAddr->setEnabled(true);
        // appendLog("Transmission thread stopped.", 0); // 你的旧日志函数
    });

    // 12. 启动线程
    workerThread->start();

    // 13. 动画效果
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
    QString summary =
        QString("Stopped. Final Total: %1 packets, %2 bytes sent.").arg(g_total_sent.load()).arg(g_total_bytes.load());
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
// 在 sender_window.cpp 中
void MainWindow::updateStats(uint64_t currSent, uint64_t currBytes) {
    // 1. 获取时间间隔
    qint64 elapsedMs = rateTimer.elapsed();

    // 过滤过短的更新（防止除以接近0的数）
    if (elapsedMs < 50) return;

    // 立即重置计时器，保证下一次计算的时间基准是“现在”
    rateTimer.restart();

    // =========================================================
    // [核心修复] 首点同步逻辑
    // 如果这是第一次检测到有数据发送 (lastTotalSent == 0 且 currSent > 0)
    // 我们无法确定这几个包是在 elapsedMs 这段时间内均匀发送的，还是刚发的。
    // 所以：只同步基准值，不计算速率，等待下一个时间周期再开始计算。
    // =========================================================
    if (lastTotalSent == 0 && currSent > 0) {
        lastTotalSent = currSent;
        lastTotalBytes = currBytes;
        // 可以选择更新一下界面数字，但不更新图表和速率
        m_dashboard.updateUI(currSent, currBytes, 0, 0);
        return;
    }

    // 2. 正常的差分计算
    uint64_t diffSent = (currSent >= lastTotalSent) ? (currSent - lastTotalSent) : 0;
    uint64_t diffBytes = (currBytes >= lastTotalBytes) ? (currBytes - lastTotalBytes) : 0;

    lastTotalSent = currSent;
    lastTotalBytes = currBytes;

    double pps = (double)diffSent * 1000.0 / elapsedMs;
    double currentBytesPerSec = (double)diffBytes * 1000.0 / elapsedMs;

    // 3. 更新 UI
    m_dashboard.updateUI(currSent, currBytes, pps, currentBytesPerSec);

    // 4. 更新图表 (自适应逻辑)
    m_chartTimeX++;

    // --- PPS 图表 ---
    m_ppsHistory.append(pps);
    if (m_ppsHistory.size() > 60) m_ppsHistory.removeFirst();

    double winMaxPPS = 0;
    for (double v : m_ppsHistory)
        if (v > winMaxPPS) winMaxPPS = v;

    seriesPPS->append(m_chartTimeX, pps);
    if (seriesPPS->count() > 60) seriesPPS->remove(0);

    double targetMaxPPS = winMaxPPS * 1.2;
    if (targetMaxPPS < 10) targetMaxPPS = 10;
    axisY_PPS->setRange(0, targetMaxPPS);

    // --- Bandwidth 图表 ---
    m_rawByteHistory.append(currentBytesPerSec);
    if (m_rawByteHistory.size() > 60) m_rawByteHistory.removeFirst();

    double winMaxBps = 0;
    for (double v : m_rawByteHistory)
        if (v > winMaxBps) winMaxBps = v;

    QString unitStr = "B/s";
    double divisor = 1.0;
    if (winMaxBps >= 1024.0 * 1024.0 * 1024.0) {
        unitStr = "GB/s";
        divisor = 1024.0 * 1024.0 * 1024.0;
    } else if (winMaxBps >= 1024.0 * 1024.0) {
        unitStr = "MB/s";
        divisor = 1024.0 * 1024.0;
    } else if (winMaxBps >= 1024.0) {
        unitStr = "KB/s";
        divisor = 1024.0;
    }

    QList<QPointF> points;
    qint64 startX = m_chartTimeX - m_rawByteHistory.size() + 1;
    for (int i = 0; i < m_rawByteHistory.size(); ++i) {
        points.append(QPointF(startX + i, m_rawByteHistory[i] / divisor));
    }
    seriesMbps->replace(points);

    chartBW->setTitle(QString("Bandwidth (%1)").arg(unitStr));
    axisY_BW->setTitleText(unitStr);

    double scaledMax = winMaxBps / divisor;
    if (scaledMax < 10.0) scaledMax = 10.0;
    axisY_BW->setRange(0, scaledMax * 1.2);

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

    // 1. 恢复主窗口几何
    if (settings.contains("window/geometry")) {
        restoreGeometry(settings.value("window/geometry").toByteArray());
    }

    // 2. 恢复底部三栏比例 (Bottom Horizontal)
    QSplitter* splitterBot = ui->grpLog->findChild<QSplitter*>("splitterBottom");
    if (splitterBot) {
        if (settings.contains("window/splitter_bottom_state")) {
            splitterBot->restoreState(settings.value("window/splitter_bottom_state").toByteArray());
        } else {
            // 默认比例 15% : 55% : 30%
            splitterBot->setSizes(QList<int>() << 150 << 550 << 300);
        }
    }

    // 3. 恢复主垂直分割 (Top vs Bottom)
    if (ui->splitterMainVertical) {
        if (settings.contains("window/splitter_main_vert_state")) {
            ui->splitterMainVertical->restoreState(settings.value("window/splitter_main_vert_state").toByteArray());
        } else {
            // 默认高度比例：Top(500px) : Bottom(200px)
            ui->splitterMainVertical->setSizes(QList<int>() << 500 << 200);
        }
    }

    // 4. 恢复顶部水平分割 (Left : Mid : Right)
    if (ui->splitterTopHorizontal) {
        if (settings.contains("window/splitter_top_horz_state")) {
            ui->splitterTopHorizontal->restoreState(settings.value("window/splitter_top_horz_state").toByteArray());
        } else {
            // 默认宽度比例：1 : 1 : 1
            ui->splitterTopHorizontal->setSizes(QList<int>() << 400 << 400 << 400);
        }
    }

    // 加载网卡选择
    QString lastInterface = settings.value("config/interface_name").toString();
    int idx = -1;
    if (!lastInterface.isEmpty()) {
        idx = ui->comboInterfaceTx->findData(lastInterface);
    }
    if (idx == -1) {
        int savedIdx = settings.value("config/interface_index", -1).toInt();
        if (savedIdx >= 0 && savedIdx < ui->comboInterfaceTx->count()) {
            idx = savedIdx;
        }
    }
    // 如果有保存的网口就选择它，否则选择第一个
    if (idx != -1 && idx < ui->comboInterfaceTx->count()) {
        ui->comboInterfaceTx->setCurrentIndex(idx);
    } else if (ui->comboInterfaceTx->count() > 0) {
        ui->comboInterfaceTx->setCurrentIndex(0);
    }

    // 加载地址信息
    ui->editSrcMac->setText(settings.value("config/src_mac", "").toString());
    ui->editDstMac->setText(settings.value("config/dst_mac", "").toString());
    ui->editSrcIp->setText(settings.value("config/src_ip", "").toString());
    QString currentDstIp = settings.value("config/dst_ip_val", "").toString();
    if (!currentDstIp.isEmpty()) ui->editDstIp->setEditText(currentDstIp);

    // [修改核心] 加载协议类型 (0=ICMP, 1=UDP, 2=TCP, 3=DNS, 4=ARP)
    int proto = settings.value("config/protocol", 0).toInt();
    switch (proto) {
        case 0:
            ui->rbIcmp->setChecked(true);
            break;
        case 1:
            ui->rbUdp->setChecked(true);
            break;
        case 2:
            ui->rbTcp->setChecked(true);
            break;
        case 3:
            ui->rbDns->setChecked(true);
            break;
        case 4:
            ui->rbArp->setChecked(true);
            break; // [新增]
    }

    // 加载 TCP 标志位
    ui->chkSyn->setChecked(settings.value("config/tcp_syn", false).toBool());
    ui->chkAck->setChecked(settings.value("config/tcp_ack", false).toBool());
    ui->chkPsh->setChecked(settings.value("config/tcp_psh", false).toBool());
    ui->chkFin->setChecked(settings.value("config/tcp_fin", false).toBool());
    ui->chkRst->setChecked(settings.value("config/tcp_rst", false).toBool());

    // 加载载荷模式
    int payMode = settings.value("config/payload_mode", 0).toInt();
    switch (payMode) {
        case 0:
            ui->rbPayRandom->setChecked(true);
            break;
        case 1:
            ui->rbPayFixed->setChecked(true);
            break;
        case 2:
            ui->rbPayCustom->setChecked(true);
            break;
    }

    // 加载其他参数
    ui->spinPktLen->setValue(settings.value("config/payload_len", 64).toInt());
    ui->spinFixVal->setValue(settings.value("config/fixed_val", 0).toInt());
    ui->editCustomData->setText(settings.value("config/custom_data", "").toString());
    ui->spinInterval->setValue(settings.value("config/interval", 10000).toInt());
    ui->spinSrcPort->setValue(settings.value("config/src_port", 10086).toInt());
    ui->spinDstPort->setValue(settings.value("config/dst_port", 10086).toInt());
    ui->editDomain->setText(settings.value("config/domain", "www.google.com").toString());

    // --- 加载右侧 OS Stack Sender 配置 ---

    // Source Interface
    QString sockIface = settings.value("sock_config/source_iface", "").toString();
    if (!sockIface.isEmpty()) {
        int sockIdx = ui->comboSockSrc->findData(sockIface);
        if (sockIdx != -1) {
            ui->comboSockSrc->setCurrentIndex(sockIdx);
        }
    }

    // Target IP
    QString savedSockIp = settings.value("sock_config/target_ip", "192.168.1.1").toString();
    if (!savedSockIp.isEmpty()) {
        ui->editSockIp->setText(savedSockIp);
    }

    // Target Port
    ui->spinSockPort->setValue(settings.value("sock_config/target_port", 8080).toInt());

    // Protocol (UDP/TCP)
    bool isSockUdp = settings.value("sock_config/is_udp", true).toBool();
    if (isSockUdp)
        ui->rbSockUdp->setChecked(true);
    else
        ui->rbSockTcp->setChecked(true);

    // Payload Size
    ui->spinSockLen->setValue(settings.value("sock_config/payload_len", 60000).toInt());

    // Interval
    ui->spinSockInt->setValue(settings.value("sock_config/interval", 1000).toInt());
}

// ============================================================================
// 保存配置 (关闭窗口或点击开始发送时调用)
// ============================================================================
void MainWindow::saveConfig() {
    QSettings settings("PacketStorm", "SenderConfig");

    settings.setValue("window/geometry", saveGeometry());

    // 1. 保存底部三栏 (Log/Table/Hex) 的比例
    QSplitter* splitterBot = ui->grpLog->findChild<QSplitter*>("splitterBottom");
    if (splitterBot) {
        settings.setValue("window/splitter_bottom_state", splitterBot->saveState());
    }

    // 2. 保存主垂直分割 (Top/Bottom) 的比例
    if (ui->splitterMainVertical) {
        settings.setValue("window/splitter_main_vert_state", ui->splitterMainVertical->saveState());
    }

    // 3. 保存顶部水平分割 (Config/Monitor/OS) 的比例
    if (ui->splitterTopHorizontal) {
        settings.setValue("window/splitter_top_horz_state", ui->splitterTopHorizontal->saveState());
    }

    // 保存 WinPcap 模块配置
    settings.setValue("config/interface_name", ui->comboInterfaceTx->currentData().toString());
    settings.setValue("config/interface_index", ui->comboInterfaceTx->currentIndex());
    settings.setValue("config/src_mac", ui->editSrcMac->text());
    settings.setValue("config/dst_mac", ui->editDstMac->text());
    settings.setValue("config/src_ip", ui->editSrcIp->text());
    settings.setValue("config/dst_ip_val", ui->editDstIp->currentText());

    // [修改核心] 保存协议类型
    int proto = 0; // Default ICMP
    if (ui->rbUdp->isChecked())
        proto = 1;
    else if (ui->rbTcp->isChecked())
        proto = 2;
    else if (ui->rbDns->isChecked())
        proto = 3;
    else if (ui->rbArp->isChecked())
        proto = 4; // [新增]
    settings.setValue("config/protocol", proto);

    settings.setValue("config/tcp_syn", ui->chkSyn->isChecked());
    settings.setValue("config/tcp_ack", ui->chkAck->isChecked());
    settings.setValue("config/tcp_psh", ui->chkPsh->isChecked());
    settings.setValue("config/tcp_fin", ui->chkFin->isChecked());
    settings.setValue("config/tcp_rst", ui->chkRst->isChecked());

    int payMode = 0;
    if (ui->rbPayFixed->isChecked())
        payMode = 1;
    else if (ui->rbPayCustom->isChecked())
        payMode = 2;
    settings.setValue("config/payload_mode", payMode);

    settings.setValue("config/payload_len", ui->spinPktLen->value());
    settings.setValue("config/fixed_val", ui->spinFixVal->value());
    settings.setValue("config/custom_data", ui->editCustomData->text());
    settings.setValue("config/interval", ui->spinInterval->value());
    settings.setValue("config/src_port", ui->spinSrcPort->value());
    settings.setValue("config/dst_port", ui->spinDstPort->value());
    settings.setValue("config/domain", ui->editDomain->text());

    // --- 保存右侧 OS Stack Sender 配置 ---

    settings.setValue("sock_config/source_iface", ui->comboSockSrc->currentData().toString());
    settings.setValue("sock_config/target_ip", ui->editSockIp->text());
    settings.setValue("sock_config/target_port", ui->spinSockPort->value());
    settings.setValue("sock_config/is_udp", ui->rbSockUdp->isChecked());
    settings.setValue("sock_config/payload_len", ui->spinSockLen->value());
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
void MainWindow::saveHistory(const QString& ip) {
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
    ui->editDstIp->setEditText(ip); // 恢复当前显示的文本
    ui->editDstIp->blockSignals(false);
}

// ============================================================================
// [修复] 日志功能恢复
// 左侧：txtLog (文本日志)
// 中间：tablePackets (数据包列表)
// 右侧：txtHexDetail (Hex视图)
// ============================================================================
void MainWindow::appendLog(const QString& msg, int level) {
    // 1. 打印到 IDE 控制台
    qDebug() << "[SYSTEM]" << msg;

    // 2. 状态栏反馈
    if (this->statusBar()) {
        this->statusBar()->showMessage(msg, 3000);
    }

    // 3. [核心] 写入左侧的 txtLog 文本框
    if (ui->txtLog) {
        QString color;
        // 定义颜色: 0=Info(Gray), 1=Success(Green), 2=Error(Red)
        if (level == 1)
            color = "#00e676"; // Green
        else if (level == 2)
            color = "#ff1744"; // Red
        else
            color = "#a0a8b7"; // Gray/White

        QString timeStr = QDateTime::currentDateTime().toString("[HH:mm:ss] ");

        // 使用 HTML 格式化颜色
        QString html = QString("<span style='color:#555;'>%1</span><span "
                               "style='color:%2;'>%3</span>")
                           .arg(timeStr)
                           .arg(color)
                           .arg(msg);

        ui->txtLog->append(html);

        // 自动滚动到底部
        QScrollBar* sb = ui->txtLog->verticalScrollBar();
        sb->setValue(sb->maximum());
    }

    // 可选：如果你还想把关键系统事件(如Error)也插入到中间的表格里，保留下面代码
    // 否则可以注释掉，保持中间表格纯净显示数据包
    /*
    if (level == 2 && ui->tablePackets) {
        // ... 插入表格的代码 ...
    }
    */
}

void MainWindow::setupHexTableStyle() {
    // 1. 设置列数 (Offset, Hex, ASCII)
    ui->tableHex->setColumnCount(3);

    // [修改] 隐藏水平表头 (Hide Headers)
    ui->tableHex->horizontalHeader()->setVisible(false);

    // 2. 基础属性设置
    ui->tableHex->verticalHeader()->setVisible(false);
    ui->tableHex->setShowGrid(false);
    ui->tableHex->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->tableHex->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableHex->setSelectionMode(QAbstractItemView::ExtendedSelection);

    // [关键] 设置字体
    QFont font("JetBrains Mono");
    font.setStyleHint(QFont::Monospace);
    font.setPixelSize(11);
    ui->tableHex->setFont(font);

    // 3. [关键] 精确计算列宽 (Minimize Widths)
    QFontMetrics fm(font);
    int charW = fm.horizontalAdvance(' '); // 单个字符宽度

    // Column 0: Offset (显示 "0000" -> 4个字符 + 左右padding)
    // 留一点余量(比如20px)给 padding
    ui->tableHex->setColumnWidth(0, (charW * 4) + 20);

    // Column 1: Hex (固定 16 字节宽度)
    // 格式: "XX XX ... XX  XX ..."
    // 前8字节 = 8*3 = 24字符
    // 后8字节 = 8*3 = 24字符
    // 中间分隔 = 1字符
    // 总计 = 49 个字符宽
    ui->tableHex->setColumnWidth(1, (charW * 50) + 20);

    // Column 2: ASCII (剩余空间全部给它，或者也设为最小)
    // 16个字符宽
    // ui->tableHex->setColumnWidth(2, (charW * 16) + 10);
    // 这里建议让 ASCII 列自动拉伸填充剩余空白，避免右边留黑
    ui->tableHex->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    // 固定前两列，防止被拉伸
    ui->tableHex->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    ui->tableHex->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Fixed);

    // 4. 设置样式表
    ui->tableHex->setStyleSheet(R"(
        QTableWidget {
            background-color: #080a10;
            border: 1px solid #1c2333;
            outline: none;
            padding-left: 5px; /* 整体左边距 */
        }
        QTableWidget::item {
            padding-top: 0px;    /* 极度紧凑 */
            padding-bottom: 0px;
        }
        QTableWidget::item:selected {
            background-color: #1a202c;
        }
    )");

    // 5. 安装代理和过滤器 (保持不变)
    m_hexDelegate = new HexRenderDelegate(this);
    ui->tableHex->setItemDelegate(m_hexDelegate);
    ui->tableHex->setMouseTracking(true);
    ui->tableHex->viewport()->installEventFilter(this);
}

void MainWindow::updateHexTable(const QByteArray& data) {
    ui->tableHex->setRowCount(0); // 清空

    int len = data.size();
    const unsigned char* p = (const unsigned char*)data.constData();

    // 强制行高，使视图紧凑
    ui->tableHex->verticalHeader()->setDefaultSectionSize(20);

    int rowCount = (len + 15) / 16;
    ui->tableHex->setRowCount(rowCount);

    for (int i = 0; i < len; i += 16) {
        int row = i / 16;

        // --- Column 0: Offset ---
        QString offsetStr = QString("%1").arg(i, 4, 16, QChar('0')).toUpper();
        ui->tableHex->setItem(row, 0, new QTableWidgetItem(offsetStr));

        // --- Column 1: Hex & Column 2: ASCII ---
        QString hexStr;
        QString asciiStr;

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                unsigned char b = p[i + j];

                // Hex: 2位大写
                hexStr += QString("%1").arg(b, 2, 16, QChar('0')).toUpper();

                // ASCII: 可见字符或点
                if (b >= 32 && b <= 126)
                    asciiStr += QChar(b);
                else
                    asciiStr += ".";

                // 分隔符逻辑 (Delegate 依赖此逻辑)
                if (j == 7)
                    hexStr += "  "; // 8字节处：双空格
                else if (j != 15)
                    hexStr += " "; // 其他：单空格
            }
            // 如果数据不足一行，不需要填充空格，留空即可
        }

        ui->tableHex->setItem(row, 1, new QTableWidgetItem(hexStr));
        ui->tableHex->setItem(row, 2, new QTableWidgetItem(asciiStr));
    }
}

bool MainWindow::eventFilter(QObject* watched, QEvent* event) {
    if (watched == ui->tableHex->viewport()) {
        if (event->type() == QEvent::MouseMove) {
            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
            QPoint pos = mouseEvent->pos();

            QModelIndex index = ui->tableHex->indexAt(pos);

            int oldRow = m_hexDelegate->hoverRow;
            int oldByte = m_hexDelegate->hoverByteIndex;

            if (index.isValid()) {
                m_hexDelegate->hoverRow = index.row();

                QRect cellRect = ui->tableHex->visualRect(index);

                // [修改] 计算相对坐标时，减去我们在 Delegate 中定义的 LEFT_PADDING
                // (4px) 这样鼠标坐标 0 点就对齐到了文字的起始点
                int relativeX = pos.x() - cellRect.left() - HexRenderDelegate::LEFT_PADDING;

                QFontMetrics fm(ui->tableHex->font());
                int charWidth = fm.horizontalAdvance(' ');
                if (charWidth <= 0) charWidth = 7;

                if (index.column() == 1) { // Hex
                    int charIdx = relativeX / charWidth;

                    if (charIdx < 0) {
                        m_hexDelegate->hoverByteIndex = -1;
                    } else if (charIdx < 24) {
                        m_hexDelegate->hoverByteIndex = charIdx / 3;
                    } else {
                        m_hexDelegate->hoverByteIndex = (charIdx - 1) / 3;
                    }
                } else if (index.column() == 2) { // ASCII
                    // ASCII 列也一样，直接除
                    m_hexDelegate->hoverByteIndex = relativeX / charWidth;
                } else {
                    m_hexDelegate->hoverRow = -1;
                    m_hexDelegate->hoverByteIndex = -1;
                }

                // 边界修正
                if (m_hexDelegate->hoverByteIndex < 0) m_hexDelegate->hoverByteIndex = -1;
                if (m_hexDelegate->hoverByteIndex > 15) m_hexDelegate->hoverByteIndex = -1;

            } else {
                m_hexDelegate->hoverRow = -1;
                m_hexDelegate->hoverByteIndex = -1;
            }

            if (oldRow != m_hexDelegate->hoverRow || oldByte != m_hexDelegate->hoverByteIndex) {
                ui->tableHex->viewport()->update();
            }
        } else if (event->type() == QEvent::Leave) {
            m_hexDelegate->hoverRow = -1;
            m_hexDelegate->hoverByteIndex = -1;
            ui->tableHex->viewport()->update();
        }
    }
    return QMainWindow::eventFilter(watched, event);
}
