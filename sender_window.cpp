#include "sender_window.h"
#include "ui_sender.h"
#include <QBoxLayout>
#include <QCloseEvent> // [新增] 窗口关闭事件
#include <QDateTime>
#include <QDebug>
#include <QGraphicsLayout>
#include <QItemSelectionModel>
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QTableView>
#include <functional>
#include <pcap.h>
#include <thread>
#include <vector>

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

    // [优化] 使用 RAII 管理内存，自动释放
    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    DWORD dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        // 缓冲区不够，重新分配
        buffer.resize(outBufLen);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        return false;
    }

    bool found = false;
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
    // buffer 自动释放，无需手动 free
    return found;
#else
    return false;
#endif
}

// 在 sender_window.cpp 中 GetAdapterInfoWinAPI 之后添加
static bool GetExtendedNetworkInfo(const QString& srcIp, QString& outMask, QString& outGateway) {
#ifdef _WIN32
    // [优化] 使用 RAII 管理内存，自动释放
    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    DWORD dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        // 缓冲区不够，重新分配
        buffer.resize(outBufLen);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &outBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        return false;
    }

    bool found = false;
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
    // buffer 自动释放，无需手动 free
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
      stopBtnEffect(nullptr), sockThread(nullptr), sockWorker(nullptr), m_resourceMonitor(nullptr),
      m_cpuWidget(nullptr), m_memoryWidget(nullptr), m_uploadWidget(nullptr), m_downloadWidget(nullptr),
      m_packetsLabel(nullptr), m_bytesLabel(nullptr), m_resourceContainer(nullptr), m_packetModel(nullptr),
      m_packetTableView(nullptr), m_isLoadingConfig(true), m_taskGroupBox(nullptr), 
      m_taskScrollArea(nullptr), m_taskContainerLayout(nullptr),
    m_aggregateTimer(new QTimer(this)) {
    ui->setupUi(this);
    setupHexTableStyle();

    // 初始化聚合定时器
    m_aggregateTimer->setInterval(1000); // 恢复为 1s 聚合一次，图表更平滑
    connect(m_aggregateTimer, &QTimer::timeout, this, &MainWindow::updateAggregateStats);
    m_aggregateTimer->start();
    rateTimer.start(); // [关键修复] 启动统计计时器，否则图表不会绘制

    // 1. 替换 SpinBox
    CommaSpinBox* newSpin = new CommaSpinBox(this);
    newSpin->setMinimum(ui->spinInterval->minimum());
    newSpin->setMaximum(ui->spinInterval->maximum());
    newSpin->setValue(ui->spinInterval->value());
    newSpin->setSingleStep(ui->spinInterval->singleStep());
    newSpin->setObjectName("spinInterval");
    newSpin->setFont(ui->spinInterval->font());
    // 样式在 UI 文件中设置
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
    // editDstMac 现在是 QComboBox，需要通过 lineEdit() 设置验证器和占位符
    QComboBox* dstMacCombo = qobject_cast<QComboBox*>(ui->editDstMac);
    if (dstMacCombo && dstMacCombo->lineEdit()) {
        dstMacCombo->lineEdit()->setValidator(macVal);
        dstMacCombo->lineEdit()->setPlaceholderText("AA:BB:CC:DD:EE:FF");
    }

    ui->editSrcMac->setPlaceholderText("AA:BB:CC:DD:EE:FF");

    // [优化] 设置 GET 按钮的固定宽度，避免被拉伸
    if (ui->btnGetMac) {
        ui->btnGetMac->setMaximumWidth(50);
        ui->btnGetMac->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    }

    // 3. 状态栏 - 用于显示鼠标所在位置控件的tooltip (样式已在 .ui 文件中定义)
    QStatusBar* bar = new QStatusBar(this);
    setStatusBar(bar);

    // 为所有子控件安装事件过滤器，用于显示鼠标所在位置控件的tooltip
    // 注意：eventFilter已经在类中实现，这里只需要确保所有控件都能接收到事件
    // 由于eventFilter会处理所有事件，我们需要在eventFilter中检查watched对象

    // 4. PPS 标签
    lblTargetPPS = new QLabel("Rate: -- pps", this);
    lblTargetPPS->setObjectName("lblTargetPPS");
    // 透明背景在 UI 文件中通过全局 QLabel 样式设置
    ui->formLayout_Param->addRow("", lblTargetPPS);

    // 5. 信号连接
    connect(ui->spinInterval, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int intervalUs) {
        if (intervalUs <= 0) {
            lblTargetPPS->setText("Target: Max Speed");
        } else {
            constexpr double MICROSECONDS_PER_SECOND = 1000000.0;
            double pps = MICROSECONDS_PER_SECOND / (double)intervalUs;
            QString ppsText;
            constexpr double MEGA_PPS = 1000000.0;
            constexpr double KILO_PPS = UIConfig::PACKETS_PER_KILOPACKET;
            if (pps >= MEGA_PPS)
                ppsText = QString::number(pps / MEGA_PPS, 'f', 2) + " Mpps";
            else if (pps >= KILO_PPS)
                ppsText = QString::number(pps / KILO_PPS, 'f', 1) + " kpps";
            else
                ppsText = QString::number((int)pps) + " pps";
            lblTargetPPS->setText("Target: " + ppsText);
        }
    });

    // 确保 grpSocketSender 的标题正确
    ui->grpSocketSender->setTitle("OS Stack Sender (Auto-Fragment)");

    // [新增] 修复协议和载荷模式切换不生效的 bug
    connect(ui->rbIcmp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbUdp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbTcp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbDns, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);
    connect(ui->rbArp, &QRadioButton::toggled, this, &MainWindow::onProtoToggled);

    connect(ui->rbPayRandom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayFixed, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);
    connect(ui->rbPayCustom, &QRadioButton::toggled, this, &MainWindow::onPayloadModeChanged);

    // 信号联动
    connect(ui->rbSockUdp, &QRadioButton::toggled, this, [this](bool checked) {
        ui->chkConnectFlood->setVisible(!checked);
        ui->sockRandomContainer->setVisible(!checked && ui->chkConnectFlood->isChecked());
    });
    // [修改] 联动逻辑：采用自动切换（Auto-Uncheck）模式，不再禁用按钮
    auto handleSpoofingToggled = [this](bool checked) {
        if (m_isLoadingConfig) return; 

        if (checked) {
            // 如果开启了伪造模式，自动取消“完整握手”的勾选
            if (ui->chkConnectFlood->isChecked()) {
                ui->chkConnectFlood->blockSignals(true); // 防止循环触发
                ui->chkConnectFlood->setChecked(false);
                ui->chkConnectFlood->blockSignals(false);
                appendLog("[SOCK] Spoofing enabled: Switching to Raw mode.", 1);
            }
        }
    };
    connect(ui->chkSockRandMac, &QCheckBox::toggled, this, handleSpoofingToggled);
    connect(ui->chkSockRandIp, &QCheckBox::toggled, this, handleSpoofingToggled);

    // 处理 ConnectFlood 勾选时的情况
    connect(ui->chkConnectFlood, &QCheckBox::toggled, this, [this](bool checked) {
        if (m_isLoadingConfig) return;

        ui->sockRandomContainer->setVisible(checked || ui->chkSockRandMac->isChecked() || ui->chkSockRandIp->isChecked());
        
        if (checked) {
            // 如果勾选了完整握手，自动取消伪造选项的勾选
            bool changed = false;
            if (ui->chkSockRandMac->isChecked()) {
                ui->chkSockRandMac->blockSignals(true);
                ui->chkSockRandMac->setChecked(false);
                ui->chkSockRandMac->blockSignals(false);
                changed = true;
            }
            if (ui->chkSockRandIp->isChecked()) {
                ui->chkSockRandIp->blockSignals(true);
                ui->chkSockRandIp->setChecked(false);
                ui->chkSockRandIp->blockSignals(false);
                changed = true;
            }
            if (changed) {
                appendLog("[SOCK] Full Handshake enabled: Spoofing disabled.", 1);
            }
        }
    });
    connect(ui->chkSockRandPort, &QCheckBox::toggled, this, [this](bool checked) {
        ui->lblSockSPort->setVisible(!checked);
        ui->spinSockSPort->setVisible(!checked);
    });

    connect(ui->editCustomData, &QLineEdit::textChanged, this, [this](const QString& text) {
        if (ui->rbPayCustom->isChecked()) {
            ui->spinPktLen->setValue(text.toUtf8().length());
        }
    });

    setupChart();
    setupTrafficTable();
    setupTaskList(); // [新增] 初始化任务列表
    
    loadConfig();

    // 信号连接
    connect(ui->btnPktAddTask, &QPushButton::clicked, this, [this](){ onStartSendClicked("", false); });
    connect(ui->btnPktAddStartTask, &QPushButton::clicked, this, [this](){ onStartSendClicked("", true); }); 
    
    connect(ui->btnSockAddTask, &QPushButton::clicked, this, [this](){ onSockStartClicked("", false); });
    connect(ui->btnSockAddStartTask, &QPushButton::clicked, this, [this](){ onSockStartClicked("", true); });

    // [修复] 在所有配置加载完成后，再连接网卡切换信号
    connect(ui->comboInterfaceTx, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
            &MainWindow::onInterfaceSelectionChanged);

    // [新增] 启动系统资源监控
    if (m_resourceMonitor) {
        m_resourceMonitor->startMonitoring(1000); // 每秒更新一次
        QString currentInterface = ui->comboInterfaceTx->currentData().toString();
        if (!currentInterface.isEmpty()) {
            m_resourceMonitor->setMonitorInterface(currentInterface);
        }
    }

    // [新增] 事件过滤器和状态同步
    installEventFilterRecursive(this);
    setupTooltips();

    bool isSpoofing = ui->chkSockRandMac->isChecked() || ui->chkSockRandIp->isChecked();
    ui->sockRandomContainer->setVisible(isSpoofing || ui->chkConnectFlood->isChecked());

    appendLog("System Ready. Configuration restored.", 1);
}

// [新增] 窗口关闭事件处理
void MainWindow::closeEvent(QCloseEvent* event) {
    // [调试] 输出关闭事件（仅在Debug模式下）
    #ifdef QT_DEBUG
    qDebug() << "closeEvent() called - saving config before closing";
    qDebug() << "Current UI state - protocol UDP:" << ui->rbUdp->isChecked()
             << "TCP:" << ui->rbTcp->isChecked()
             << "ICMP:" << ui->rbIcmp->isChecked()
             << "src_port:" << ui->spinSrcPort->value()
             << "dst_port:" << ui->spinDstPort->value();
    #endif
    
    // 保存配置
    saveConfig();
    
    // 接受关闭事件
    event->accept();
}

MainWindow::~MainWindow() {
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

    // [新增] 停止资源监控
    if (m_resourceMonitor) {
        m_resourceMonitor->stopMonitoring();
        delete m_resourceMonitor;
    }

    if (stopBtnAnim) {
        stopBtnAnim->stop();
        delete stopBtnAnim;
    }
    delete ui;
}

// ============================================================================
// [新增] 辅助解析函数
// ============================================================================
void MainWindow::parseMac(const QString& s, unsigned char* buf) {
    static const QRegularExpression regex("[:-]");
    QStringList p = s.split(regex);
    for (int i = 0; i < 6 && i < p.size(); ++i) {
        buf[i] = (unsigned char)p[i].toUInt(nullptr, 16);
    }
}

void MainWindow::parseIp(const QString& s, unsigned char* buf) {
    QStringList p = s.split('.');
    for (int i = 0; i < 4 && i < p.size(); ++i) {
        buf[i] = (unsigned char)p[i].toUInt();
    }
}

// ============================================================================
// [新增] 右侧 Socket 模块实现 (OS Stack Sender)
// ============================================================================
void MainWindow::onSockStartClicked(const QString& existingTaskId, bool startImmediately) {
    // 1. 保存配置
    saveConfig();

    QString taskId = existingTaskId;
    SendingTask* task = nullptr;
    QString protoName;

    if (taskId.isEmpty()) {
        // 2. 构造任务 ID 和信息 (新任务)
        protoName = ui->rbSockUdp->isChecked() ? "SOCK_UDP" : "SOCK_TCP";
        QString target = ui->editSockIp->text();
        taskId = QString("%1_%2_%3").arg(protoName).arg(target).arg(QDateTime::currentMSecsSinceEpoch() % 10000);

        // 3. 创建任务
        task = new SendingTask();
        task->taskId = taskId;
        task->proto = protoName;
        task->target = target;
        task->lastUpdateTimer.start(); // [新增]
        m_tasks[taskId] = task;
    } else {
        task = m_tasks[taskId];
        protoName = task->proto;
        task->lastUpdateTimer.restart(); // [新增]
        task->lastSentCount = 0;         // [修复] 重启时重置上次计数，避免速率跳变或为0
    }

    task->isRunning = startImmediately;
    task->stopFlag = !startImmediately;

    // 4. 创建工作线程和 Worker
    if (!task->thread) task->thread = new QThread(this);
    SocketWorker* sw = new SocketWorker();
    task->worker = sw;

    // 5. 填充配置
    memset(&sw->config, 0, sizeof(SocketConfig));
    std::string ip = ui->editSockIp->text().toStdString();
    strncpy(sw->config.target_ip, ip.c_str(), sizeof(sw->config.target_ip) - 1);

    QString selectedPcapName = ui->comboSockSrc->currentData().toString();
    if (selectedPcapName.isEmpty()) {
        strcpy(sw->config.source_ip, "0.0.0.0");
    } else {
        QString mac, srcIp;
        if (GetAdapterInfoWinAPI(selectedPcapName, mac, srcIp) && !srcIp.isEmpty() && srcIp != "0.0.0.0") {
            strncpy(sw->config.source_ip, srcIp.toStdString().c_str(), sizeof(sw->config.source_ip) - 1);
        } else {
            strcpy(sw->config.source_ip, "0.0.0.0");
        }
    }

    sw->config.target_port = ui->spinSockPort->value();
    
    // [修复] 使用任务保存的协议类型
    sw->config.is_udp = (protoName == "SOCK_UDP");
    
    sw->config.is_connect_only = ui->chkConnectFlood->isChecked();
    sw->config.use_random_src_port = ui->chkSockRandPort->isChecked();
    sw->config.use_random_src_mac = ui->chkSockRandMac->isChecked();
    sw->config.use_random_src_ip = ui->chkSockRandIp->isChecked();
    sw->config.use_random_seq = ui->chkSockRandSeq->isChecked();
    sw->config.source_port = (unsigned short)ui->spinSockSPort->value();
    strncpy(sw->config.dev_name, selectedPcapName.toStdString().c_str(), sizeof(sw->config.dev_name) - 1);
    
    QString baseMac = ui->editSrcMac->text();
    parseMac(baseMac, sw->config.src_mac);

    sw->config.payload_len = ui->spinSockLen->value();
    sw->config.interval_us = ui->spinSockInt->value();
    sw->config.stop_flag = &task->stopFlag;
    sw->config.user_data = sw;

    // 6. 连接信号
    sw->moveToThread(task->thread);
    connect(task->thread, &QThread::started, sw, &SocketWorker::doWork);
    connect(sw, &SocketWorker::workFinished, task->thread, &QThread::quit);
    connect(sw, &SocketWorker::statsUpdated, this, [this, taskId](uint64_t s, uint64_t b){
        updateTaskStats(taskId, s, b);
    });
    connect(sw, &SocketWorker::logUpdated, this, [this](QString msg, int level){ appendLog(msg, level); });

    // 7. 创建任务卡片 (仅新任务需要创建 UI)
    if (existingTaskId.isEmpty()) {
        QWidget* card = new QWidget();
        card->setFixedHeight(70); 
        card->setObjectName("taskCard");
        
        QHBoxLayout* cardLayout = new QHBoxLayout(card);
        cardLayout->setContentsMargins(10, 5, 10, 5);
        cardLayout->setSpacing(12);

        // [列1] 按钮
        QVBoxLayout* btnVly = new QVBoxLayout();
        btnVly->setSpacing(4);
        QPushButton* btnSS = new QPushButton(startImmediately ? "Stop" : "Start");
        btnSS->setObjectName(startImmediately ? "btnTaskStop" : "btnTaskStart");
        btnSS->setFixedSize(85, 28); 
        
        QPushButton* btnDel = new QPushButton("Delete"); 
        btnDel->setFixedSize(85, 28); 
        btnDel->setObjectName("btnTaskDelete");

        btnVly->addWidget(btnSS);
        btnVly->addWidget(btnDel);
        cardLayout->addLayout(btnVly);

        // [列2] 信息
        QVBoxLayout* infoVly = new QVBoxLayout();
        infoVly->setSpacing(0);
        QLabel* lblProto = new QLabel(protoName);
        lblProto->setObjectName("lblProtoSocket");
        QLabel* lblTarget = new QLabel(task->target);
        lblTarget->setObjectName("lblTargetSmall");
        infoVly->addWidget(lblProto);
        infoVly->addWidget(lblTarget);
        cardLayout->addLayout(infoVly);

        cardLayout->addStretch();

        // [列3] 统计
        QLabel* lblStats = new QLabel("Sent: 0\nRate: Updating...");
        lblStats->setObjectName("lblStatsSmall");
        lblStats->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        cardLayout->addWidget(lblStats);

        task->cardWidget = card;
        task->lblStats = lblStats;
        task->btnStartStop = btnSS;

        m_taskContainerLayout->insertWidget(m_taskContainerLayout->count() - 1, card);

        connect(btnSS, &QPushButton::clicked, this, [this, taskId](){ onTaskStartStopClicked(taskId); });
        connect(btnDel, &QPushButton::clicked, this, [this, taskId](){ onTaskRemoveClicked(taskId); });
    } else {
        // 重启时更新按钮状态
        if (task->btnStartStop) {
            task->btnStartStop->setText("Stop");
            task->btnStartStop->setObjectName("btnTaskStop");
            task->btnStartStop->style()->unpolish(task->btnStartStop);
            task->btnStartStop->style()->polish(task->btnStartStop);
        }
    }

    // 8. 启动
    if (startImmediately) {
        task->thread->start();
        appendLog(QString("Task %1 started.").arg(taskId), 1);
    } else {
        appendLog(QString("Task %1 added (Stopped).").arg(taskId), 0);
    }
}

void MainWindow::onSockStopClicked() {
    // 设置停止标志，线程循环检测到后会退出
    g_is_sock_sending = false;
    // ui->btnSockStop->setEnabled(false); // [移除] 现在按钮作为工厂按钮，应始终启用
    
    // 保存配置（确保停止时的配置被保存）
    saveConfig();
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
        axis->setRange(0, UIConfig::CHART_TIME_RANGE);
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
    axisY_PPS->setRange(0, UIConfig::CHART_PPS_MAX_Y);
    chartPPS->addAxis(axisY_PPS, Qt::AlignLeft);
    seriesPPS->attachAxis(axisY_PPS);

    viewPPS = new QChartView(chartPPS);
    viewPPS->setRenderHint(QPainter::Antialiasing);

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

    // =========================================================
    // 3. 添加到布局 (垂直排列)
    // =========================================================
    // 这里的 ui->grpChart 是我们在 UI 设计器里预留的 GroupBox
    QVBoxLayout* layout = new QVBoxLayout(ui->grpChart);
    layout->setContentsMargins(UIConfig::CHART_LAYOUT_MARGIN_LEFT, UIConfig::CHART_LAYOUT_MARGIN_TOP,
                               UIConfig::CHART_LAYOUT_MARGIN_RIGHT, UIConfig::CHART_LAYOUT_MARGIN_BOTTOM);
    layout->setSpacing(UIConfig::CHART_LAYOUT_SPACING); // 两个图表之间的间距

    layout->addWidget(viewPPS); // 上面放 PPS
    layout->addWidget(viewBW);  // 下面放 BW

    // [新增] 添加系统资源监控区域
    setupResourceMonitor();
    layout->addWidget(m_resourceContainer);

    // 只有第一次需要设置伸缩因子，保证平分高度
    // 但在 QVBoxLayout 中默认就是平分的

    m_chartTimeX = 0;
    m_maxPPS = UIConfig::CHART_PPS_DEFAULT_MAX;
    m_maxMbps = UIConfig::CHART_BW_DEFAULT_MAX;

    // [关键修复] 强制启用按钮，样式已由 .ui 文件统一管理
    ui->btnPktAddTask->setEnabled(true);
    ui->btnPktAddStartTask->setEnabled(true);
    ui->btnSockAddTask->setEnabled(true);
    ui->btnSockAddStartTask->setEnabled(true);
}

void MainWindow::loadInterfaces() {
    ui->comboInterfaceTx->clear();

    // [新增] 清空并初始化右侧 Socket 源列表
    // [新增] 填充右侧 (Socket)
    ui->comboSockSrc->clear();
    ui->comboSockSrc->addItem("Auto (Let OS Decide)",
                              ""); // 默认选项，对应 IP 为空

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
        ui->comboSockSrc->addItem(desc, pcapName);
    }
    pcap_freealldevs(alldevs);

    // [修复] 信号连接已移动到构造函数中 loadConfig() 之后
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

    // [新增] 更新资源监控的网卡选择
    if (m_resourceMonitor) {
        m_resourceMonitor->setMonitorInterface(pcapName);
    }

    // 保存当前选择的网口（仅在非初始化/加载配置期间保存）
    if (!m_isLoadingConfig) {
        saveConfig();
    }
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
                // editDstMac 现在是 QComboBox，使用 setEditText()
                // editDstMac 现在是 QComboBox，使用 setEditText()
                QComboBox* dstMacCombo = qobject_cast<QComboBox*>(ui->editDstMac);
                if (dstMacCombo) {
                    dstMacCombo->setEditText(macStr);
                    dstMacCombo->setFocus();
                    dstMacCombo->lineEdit()->selectAll();
                }

                // 提示用户解析的是哪个 IP 的 MAC
                appendLog("MAC Resolved (" + actualArpTargetStr + "): " + macStr, 1);

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
        ui->spinPktLen->setProperty("arpMode", true);
        ui->spinPktLen->style()->unpolish(ui->spinPktLen);
        ui->spinPktLen->style()->polish(ui->spinPktLen);
        // 提示用户：广播 ARP 请将 DstMAC 设为 FF:FF...
        QComboBox* dstMacCombo = qobject_cast<QComboBox*>(ui->editDstMac);
        if (dstMacCombo) {
            QString currentMac = dstMacCombo->currentText();
            if (currentMac.isEmpty()) {
                dstMacCombo->setEditText("FF:FF:FF:FF:FF:FF");
            }
        }
    } else {
        ui->spinPktLen->setEnabled(true);
        ui->spinPktLen->setProperty("arpMode", false);
        ui->spinPktLen->style()->unpolish(ui->spinPktLen);
        ui->spinPktLen->style()->polish(ui->spinPktLen);
    }
}

// ============================================================================
// Wireshark 风格辅助函数
// ============================================================================

// ============================================================================
// [新增] 初始化任务列表 - 现在从 UI 文件加载 (卡片式)
// ============================================================================
void MainWindow::setupTaskList() {
    // 1. 直接引用 UI 中定义的控件
    m_taskGroupBox = ui->taskManager;
    m_taskScrollArea = ui->taskScrollArea;
    m_taskContainerLayout = qobject_cast<QVBoxLayout*>(ui->taskContainer->layout());

    if (!m_taskContainerLayout) {
        m_taskContainerLayout = new QVBoxLayout(ui->taskContainer);
        m_taskContainerLayout->setContentsMargins(5, 5, 5, 5);
        m_taskContainerLayout->setSpacing(8);
    }
    
    // 2. 初始垫底，让条目向上对齐
    m_taskContainerLayout->addStretch();

    // 3. 连接全局控制按钮
    connect(ui->btnStartAll, &QPushButton::clicked, this, &MainWindow::onStartAllClicked);
    connect(ui->btnStopAll, &QPushButton::clicked, this, &MainWindow::onStopAllClicked);
    connect(ui->btnClearAll, &QPushButton::clicked, this, [this]() {
        // 获取所有任务 ID，并逐个执行安全删除逻辑
        QStringList taskIds = m_tasks.keys();
        for (const QString& taskId : taskIds) {
            onTaskRemoveClicked(taskId);
        }
        appendLog("All tasks have been cleared from manager.", 1);
    });

    // 为全局按钮安装事件过滤器实现悬停动画
    ui->btnStartAll->installEventFilter(this);
    ui->btnStopAll->installEventFilter(this);
    ui->btnClearAll->installEventFilter(this);
}

void MainWindow::onAddTaskClicked() {
    // 这个函数可以由一个新的按钮触发，或者直接复用 onStartSendClicked
    onStartSendClicked();
}

void MainWindow::onStartAllClicked() {
    for (auto it = m_tasks.begin(); it != m_tasks.end(); ++it) {
        if (!it.value()->isRunning) {
            onTaskStartStopClicked(it.key());
        }
    }
}

void MainWindow::onStopAllClicked() {
    for (auto it = m_tasks.begin(); it != m_tasks.end(); ++it) {
        if (it.value()->isRunning) {
            onTaskStartStopClicked(it.key());
        }
    }
}

void MainWindow::onTaskStartStopClicked(const QString& taskId) {
    if (!m_tasks.contains(taskId)) return;
    SendingTask* task = m_tasks[taskId];

    if (task->isRunning) {
        // 停止任务
        task->stopFlag = true;
        task->isRunning = false;
        appendLog(QString("Task %1 stopped.").arg(taskId), 0);
    } else {
        // 启动任务：彻底清理旧线程和旧 Worker，然后重建
        task->stopFlag = false;
        task->isRunning = true;
        
        if (task->thread) {
            task->thread->quit();
            task->thread->wait();
            delete task->thread;
            task->thread = nullptr;
        }
        if (task->worker) {
            delete task->worker;
            task->worker = nullptr;
        }

        // 根据协议类型重建对应的 Worker
        if (task->proto.startsWith("SOCK")) {
            onSockStartClicked(taskId);
        } else {
            onStartSendClicked(taskId);
        }
        return; // onStartSendClicked/onSockStartClicked 会处理剩下的逻辑
    }

    // 更新按钮文字和样式 (仅针对停止状态，启动状态在 onStartXXX 函数中处理)
    if (task->btnStartStop) {
        task->btnStartStop->setText(task->isRunning ? "Stop" : "Start");
        task->btnStartStop->setObjectName(task->isRunning ? "btnTaskStop" : "btnTaskStart");
        // 强制刷新样式
        task->btnStartStop->style()->unpolish(task->btnStartStop);
        task->btnStartStop->style()->polish(task->btnStartStop);
    }
}

void MainWindow::onTaskRemoveClicked(const QString& taskId) {
    if (!m_tasks.contains(taskId)) return;
    
    SendingTask* task = m_tasks[taskId];
    
    // 1. 如果任务正在运行，先执行停止逻辑
    if (task->isRunning || (task->thread && task->thread->isRunning())) {
        task->stopFlag = true;
        task->isRunning = false;
        appendLog(QString("Task %1 stopping before deletion...").arg(taskId), 0);
        
        if (task->thread) {
            task->thread->quit();
            task->thread->wait();
        }
        appendLog(QString("Task %1 stopped.").arg(taskId), 1);
    }
    
    // 2. 执行移除和清理逻辑
    if (task->cardWidget) {
        task->cardWidget->hide();
        m_taskContainerLayout->removeWidget(task->cardWidget);
        task->cardWidget->deleteLater();
    }

    m_tasks.remove(taskId);
    delete task;
    
    appendLog(QString("Task %1 has been deleted.").arg(taskId), 0);
}

void MainWindow::updateAggregateStats() {
    uint64_t totalSent = 0;
    uint64_t totalBytes = 0;

    // 汇总所有活动任务的数据
    for (auto task : m_tasks) {
        totalSent += task->sentCount;
        totalBytes += task->byteCount;
    }

    // 更新底部总数显示 (不再依赖全局原子变量，而是使用任务汇总值)
    updateStatsDisplay(totalSent, totalBytes);

    // 驱动图表更新 (updateStats 内部会自动处理 delta 计算和曲线绘制)
    updateStats(totalSent, totalBytes);
}

void MainWindow::updateTaskStats(const QString& taskId, uint64_t sent, uint64_t bytes) {
    if (!m_tasks.contains(taskId)) return;
    SendingTask* task = m_tasks[taskId];
    task->sentCount = sent;
    task->byteCount = bytes;

    // 计算单任务速率 (恢复频率为 500ms)
    qint64 elapsed = task->lastUpdateTimer.elapsed();
    if (elapsed >= 500) {
        uint64_t diff = (sent >= task->lastSentCount) ? (sent - task->lastSentCount) : sent;
        double pps = (double)diff * 1000.0 / elapsed;
        
        task->lastSentCount = sent;
        task->lastUpdateTimer.restart();

        if (task->lblStats) {
            QString ppsStr;
            if (pps >= 1000000.0) ppsStr = QString::number(pps / 1000000.0, 'f', 2) + " Mpps";
            else if (pps >= 1000.0) ppsStr = QString::number(pps / 1000.0, 'f', 1) + " kpps";
            else ppsStr = QString::number((int)pps) + " pps";

            task->lblStats->setText(QString("Sent: %1\nRate: %2").arg(sent).arg(ppsStr));
        }
    }
}

// ============================================================================
// [MVC] 初始化表格 - 使用 Model/View 架构
// ============================================================================
void MainWindow::setupTrafficTable() {
    // [MVC] 如果 Model 已存在，说明已经初始化过，直接返回
    if (m_packetModel && m_packetTableView) {
        return;
    }

    // 1. 创建 Model
    if (!m_packetModel) {
        m_packetModel = new PacketTableModel(this);
    }

    // 2. [MVC] 将 UI 文件中的 QTableWidget 替换为 QTableView
    // 检查 ui->tablePackets 是否存在且有效（如果已经被替换，parentWidget 会是 nullptr）
    if (!ui->tablePackets) {
        // 如果 tablePackets 不存在，可能是已经被替换了，直接返回
        return;
    }

    // 获取 QTableWidget 的父容器和布局信息
    QWidget* parentWidget = ui->tablePackets->parentWidget();
    if (!parentWidget) {
        // 如果没有父容器，说明可能已经被删除或替换了
        // 如果 m_packetTableView 已存在，说明已经初始化过
        if (m_packetTableView) {
            return; // 已经初始化，直接返回
        }
        // 否则无法替换，返回
        return;
    }

    QBoxLayout* parentLayout = qobject_cast<QBoxLayout*>(parentWidget->layout());
    int widgetIndex = -1;

    // 尝试查找 QTableWidget 在布局中的位置
    if (parentLayout) {
        for (int i = 0; i < parentLayout->count(); ++i) {
            QLayoutItem* item = parentLayout->itemAt(i);
            if (item && item->widget() == ui->tablePackets) {
                widgetIndex = i;
                break;
            }
        }
    }

    // 创建 QTableView 替换 QTableWidget
    QTableView* packetTableView = new QTableView(this);
    packetTableView->setObjectName("tablePackets"); // 保持相同的对象名
    packetTableView->setModel(m_packetModel);       // 绑定 Model

    // 3. 样式表设置（适配 QTableView）
    // 默认样式已在 .ui 文件中定义
    packetTableView->setObjectName("tablePackets"); 

    // 4. 基础属性
    packetTableView->verticalHeader()->setVisible(false);
    packetTableView->verticalHeader()->setDefaultSectionSize(18);
    packetTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // 5. 滚动条和列宽设置
    packetTableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    packetTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    packetTableView->horizontalHeader()->setStretchLastSection(false);

    // 设置初始列宽
    packetTableView->setColumnWidth(PacketTableModel::ColNo, UIConfig::TABLE_COL_WIDTH_NO);
    packetTableView->setColumnWidth(PacketTableModel::ColTime, UIConfig::TABLE_COL_WIDTH_TIME);
    packetTableView->setColumnWidth(PacketTableModel::ColSource, UIConfig::TABLE_COL_WIDTH_ADDRESS);
    packetTableView->setColumnWidth(PacketTableModel::ColDestination, UIConfig::TABLE_COL_WIDTH_ADDRESS);
    packetTableView->setColumnWidth(PacketTableModel::ColProtocol, UIConfig::TABLE_COL_WIDTH_PROTO);
    packetTableView->setColumnWidth(PacketTableModel::ColLength, UIConfig::TABLE_COL_WIDTH_LEN);
    packetTableView->setColumnWidth(PacketTableModel::ColInfo, UIConfig::TABLE_COL_WIDTH_INFO);

    // 6. 选择模式配置
    packetTableView->setShowGrid(false);
    packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTableView->setSelectionMode(QAbstractItemView::SingleSelection);

    // 7. [MVC] 替换布局中的 QTableWidget
    if (parentLayout && widgetIndex >= 0) {
        // 移除旧的 QTableWidget
        QLayoutItem* item = parentLayout->takeAt(widgetIndex);
        if (item) {
            QWidget* oldWidget = item->widget();
            if (oldWidget) {
                oldWidget->hide();
                oldWidget->setParent(nullptr);
                oldWidget->deleteLater();
            }
            delete item;
        }

        // 添加新的 QTableView（QBoxLayout 有 insertWidget 方法）
        parentLayout->insertWidget(widgetIndex, packetTableView);
    } else if (parentWidget && ui->tablePackets) {
        // 如果找不到 QBoxLayout，尝试直接替换父容器的子控件
        // 隐藏旧的 QTableWidget
        QTableWidget* oldTable = ui->tablePackets;
        oldTable->hide();
        oldTable->setParent(nullptr);
        oldTable->deleteLater();
        // 注意：不能直接设置 ui->tablePackets = nullptr，因为它是 UI 文件生成的成员
        // 但我们可以通过检查 parentWidget 来判断是否已被替换

        // 将新的 QTableView 添加到父容器
        // 如果父容器已有布局，添加到布局中；否则创建新布局
        QLayout* existingLayout = parentWidget->layout();
        if (existingLayout) {
            // 如果已有布局但不是 QBoxLayout，尝试添加到最后
            if (QBoxLayout* boxLayout = qobject_cast<QBoxLayout*>(existingLayout)) {
                boxLayout->addWidget(packetTableView);
            } else {
                // 其他类型的布局，创建包装布局
                QVBoxLayout* wrapperLayout = new QVBoxLayout();
                wrapperLayout->setContentsMargins(0, 0, 0, 0);
                wrapperLayout->addWidget(packetTableView);
                parentWidget->setLayout(wrapperLayout);
            }
        } else {
            // 没有布局，创建新布局
            QVBoxLayout* newLayout = new QVBoxLayout(parentWidget);
            newLayout->setContentsMargins(0, 0, 0, 0);
            newLayout->addWidget(packetTableView);
            parentWidget->setLayout(newLayout);
        }
    }

    // 8. [MVC] 信号连接 - 使用 QTableView 的选择模型
    // QTableView 在设置 Model 后会自动创建 selectionModel
    QItemSelectionModel* selectionModel = packetTableView->selectionModel();
    if (selectionModel) {
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this,
                [this, packetTableView](const QItemSelection& selected, const QItemSelection& deselected) {
                    Q_UNUSED(deselected);
                    if (selected.indexes().isEmpty() || !m_packetModel) return;

                    QModelIndex index = selected.indexes().first();
                    if (!index.isValid()) return;

                    QByteArray data = m_packetModel->getRawData(index.row());
                    if (!data.isEmpty()) {
                        updateHexTable(data);
                    }
                    if (packetTableView && packetTableView->hasFocus()) {
                        ui->chkAutoScroll->setChecked(false);
                    }
                });
    }

    // 9. 保存 QTableView 的引用（用于后续操作）
    m_packetTableView = packetTableView;
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
            if (data.size() > 42) { // 需要至少 34 + 8 字节（ICMP 头）
                uint8_t type = bytes[34];
                // ICMP Echo 包结构（从偏移 34 开始）:
                // bytes[34] = type (1 byte)
                // bytes[35] = code (1 byte)
                // bytes[36-37] = checksum (2 bytes)
                // bytes[38-39] = ident (2 bytes) - 这是 id
                // bytes[40-41] = seq (2 bytes) - 这是序列号
                uint16_t ident = (bytes[38] << 8) | bytes[39]; // ident (id)
                uint16_t seq = (bytes[40] << 8) | bytes[41];   // seq (序列号)
                if (type == 8)
                    info.info = QString("Echo (ping) request  id=0x%1 seq=%2").arg(ident, 0, 16).arg(seq);
                else if (type == 0)
                    info.info = QString("Echo (ping) reply    id=0x%1 seq=%2").arg(ident, 0, 16).arg(seq);
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

void MainWindow::onStartSendClicked(const QString& existingTaskId, bool startImmediately) {
    // 1. 保存配置
    saveConfig();

    QString taskId = existingTaskId;
    SendingTask* task = nullptr;
    QString protoName;

    if (taskId.isEmpty()) {
        // 2. 构造任务 ID 和基本信息 (新任务)
        protoName = "ICMP";
        if (ui->rbUdp->isChecked()) protoName = "UDP";
        else if (ui->rbTcp->isChecked()) protoName = "TCP";
        else if (ui->rbDns->isChecked()) protoName = "DNS";
        else if (ui->rbArp->isChecked()) protoName = "ARP";

        QString target = ui->editDstIp->currentText();
        taskId = QString("%1_%2_%3").arg(protoName).arg(target).arg(QDateTime::currentMSecsSinceEpoch() % 10000);

        // 3. 创建任务结构
        task = new SendingTask();
        task->taskId = taskId;
        task->proto = protoName;
        task->target = target;
        task->lastUpdateTimer.start(); // [新增]
        m_tasks[taskId] = task;
    } else {
        task = m_tasks[taskId];
        protoName = task->proto;
        task->lastUpdateTimer.restart(); // [新增]
        task->lastSentCount = 0;         // [修复] 重启时重置上次计数，避免速率跳变或为0
    }

    task->isRunning = startImmediately;
    task->stopFlag = !startImmediately;

    // 4. 创建工作线程和 Worker
    if (!task->thread) task->thread = new QThread(this);
    PacketWorker* pw = new PacketWorker();
    task->worker = pw;

    // 5. 填充 Worker 配置 (从当前 UI 获取)
    // ... (rest of the config filling logic) ...
    memset(&pw->config, 0, sizeof(SenderConfig));
    std::string dev = ui->comboInterfaceTx->currentData().toString().toStdString();
    strncpy(pw->config.dev_name, dev.c_str(), sizeof(pw->config.dev_name) - 1);

    parseMac(ui->editSrcMac->text(), pw->config.src_mac);
    parseMac(qobject_cast<QComboBox*>(ui->editDstMac)->currentText(), pw->config.des_mac);
    parseIp(ui->editSrcIp->text(), pw->config.src_ip);
    parseIp(ui->editDstIp->currentText(), pw->config.des_ip);

    pw->config.send_interval_us = ui->spinInterval->value();
    pw->config.src_port = ui->spinSrcPort->value();
    pw->config.dst_port = ui->spinDstPort->value();

    // [修复] 使用任务保存的协议类型，而不是当前 UI 选中的类型
    if (protoName == "UDP") pw->config.packet_type = UDP_PACKAGE;
    else if (protoName == "TCP") pw->config.packet_type = TCP_PACKAGE;
    else if (protoName == "DNS") pw->config.packet_type = DNS_PACKAGE;
    else if (protoName == "ARP") pw->config.packet_type = ARP_PACKAGE;
    else pw->config.packet_type = ICMP_PACKAGE;

    if (protoName == "TCP") {
        int flags = 0;
        if (ui->chkFin->isChecked()) flags |= 0x01;
        if (ui->chkSyn->isChecked()) flags |= 0x02;
        if (ui->chkRst->isChecked()) flags |= 0x04;
        if (ui->chkPsh->isChecked()) flags |= 0x08;
        if (ui->chkAck->isChecked()) flags |= 0x10;
        pw->config.tcp_flags = flags;
    }

    std::string domain = ui->editDomain->text().toStdString();
    strncpy(pw->config.dns_domain, domain.c_str(), sizeof(pw->config.dns_domain) - 1);

    pw->config.payload_len = ui->spinPktLen->value();
    if (ui->rbPayFixed->isChecked()) {
        pw->config.payload_mode = PAYLOAD_FIXED;
        pw->config.fixed_byte_val = (unsigned char)ui->spinFixVal->value();
    } else if (ui->rbPayCustom->isChecked()) {
        pw->config.payload_mode = PAYLOAD_CUSTOM;
        pw->customDataBuffer = ui->editCustomData->text().toUtf8();
    } else {
        pw->config.payload_mode = PAYLOAD_RANDOM;
    }

    pw->config.stop_flag = &task->stopFlag;
    pw->config.user_data = pw;

    // 6. 连接信号
    pw->moveToThread(task->thread);
    connect(task->thread, &QThread::started, pw, &PacketWorker::doSendWork);
    connect(pw, &PacketWorker::workFinished, task->thread, &QThread::quit);
    connect(pw, &PacketWorker::statsUpdated, this, [this, taskId](uint64_t s, uint64_t b){
        updateTaskStats(taskId, s, b);
    });
    connect(pw, &PacketWorker::hexUpdated, this, [this](QByteArray data){
        // 只有最后一个活动任务显示在流量表里，或者这里可以做更复杂的逻辑
        // 为简化，我们让所有任务的采样都显示在主流量表
        if (!m_packetModel) return;
        m_packetCount++;
        PacketInfo parseInfo = parsePacket(data);
        PacketTableModel::PacketInfo modelInfo;
        modelInfo.packetNumber = m_packetCount;
        modelInfo.timestamp = QDateTime::currentDateTime();
        modelInfo.src = parseInfo.src;
        modelInfo.dst = parseInfo.dst;
        modelInfo.proto = parseInfo.proto;
        modelInfo.length = parseInfo.length;
        modelInfo.info = parseInfo.info;
        modelInfo.rawData = data;
        m_packetModel->addPacket(modelInfo);
        if (ui->chkAutoScroll->isChecked() && m_packetTableView) {
            m_packetTableView->scrollToBottom();
            updateHexTable(data);
        }
    });

    // 7. 创建任务卡片 (仅新任务需要创建 UI)
    if (existingTaskId.isEmpty()) {
        QWidget* card = new QWidget();
        card->setFixedHeight(70); 
        card->setObjectName("taskCard");
        
        QHBoxLayout* cardLayout = new QHBoxLayout(card);
        cardLayout->setContentsMargins(10, 5, 10, 5);
        cardLayout->setSpacing(12);

        // [列1] 操作按钮
        QVBoxLayout* btnVly = new QVBoxLayout();
        btnVly->setSpacing(4); 
        QPushButton* btnSS = new QPushButton(startImmediately ? "Stop" : "Start");
        btnSS->setObjectName(startImmediately ? "btnTaskStop" : "btnTaskStart");
        btnSS->setFixedSize(85, 28); 
        
        QPushButton* btnDel = new QPushButton("Delete"); 
        btnDel->setFixedSize(85, 28); 
        btnDel->setObjectName("btnTaskDelete");

        btnVly->addWidget(btnSS);
        btnVly->addWidget(btnDel);
        cardLayout->addLayout(btnVly);

        // [列2] 任务核心信息
        QVBoxLayout* infoVly = new QVBoxLayout();
        infoVly->setSpacing(0);
        QLabel* lblProto = new QLabel(protoName);
        lblProto->setObjectName("lblProtoWinPcap");
        QLabel* lblTarget = new QLabel(task->target);
        lblTarget->setObjectName("lblTargetSmall");
        infoVly->addWidget(lblProto);
        infoVly->addWidget(lblTarget);
        cardLayout->addLayout(infoVly);

        cardLayout->addStretch();

        // [列3] 统计数据
        QLabel* lblStats = new QLabel("Sent: 0\nRate: Updating...");
        lblStats->setObjectName("lblStatsSmall");
        lblStats->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        cardLayout->addWidget(lblStats);

        task->cardWidget = card;
        task->lblStats = lblStats;
        task->btnStartStop = btnSS;

        // 插入到布局中 (放在 stretch 之前)
        m_taskContainerLayout->insertWidget(m_taskContainerLayout->count() - 1, card);

        connect(btnSS, &QPushButton::clicked, this, [this, taskId](){ onTaskStartStopClicked(taskId); });
        connect(btnDel, &QPushButton::clicked, this, [this, taskId](){ onTaskRemoveClicked(taskId); });
    } else {
        // 重启任务时更新按钮显示
        if (task->btnStartStop) {
            task->btnStartStop->setText("Stop");
            task->btnStartStop->setObjectName("btnTaskStop");
            task->btnStartStop->style()->unpolish(task->btnStartStop);
            task->btnStartStop->style()->polish(task->btnStartStop);
        }
    }

    // 8. 启动线程
    if (startImmediately) {
        task->thread->start();
        appendLog(QString("Task %1 started.").arg(taskId), 1);
    } else {
        appendLog(QString("Task %1 added (Stopped).").arg(taskId), 0);
    }
}

void MainWindow::onStopSendClicked() {
    // 1. 停止发送标志
    g_is_sending = false;
    // ui->btnStopSend->setEnabled(false); // [移除] 始终启用

    // ==============================================================================
    // [修复核心] 不要在这里调用 updateStats！
    // updateStats 会重置 rateTimer，导致后续的排队信号计算出的时间间隔极小(1ms)，
    // 从而产生巨大的 PPS 尖峰 (Spike) 或者 0 值 (Dip)。
    // ==============================================================================

    // 2. 我们只更新底部的"数字"显示，确保显示的是最终的原子计数
    // 参数3和4传 0，表示停止时的瞬时速率为 0
    updateStatsDisplay(g_total_sent.load(), g_total_bytes.load());

    // 注意：中间的速度显示（Upload/Download）会继续显示网卡的总流量
    // 这是正常的，因为速率统计独立于发送状态，软件启动时就开始统计

    // 3. 保存配置（确保停止时的配置被保存）
    saveConfig();

    // 4. 记录日志
    QString summary =
        QString("Stopped. Final Total: %1 packets, %2 bytes sent.").arg(g_total_sent.load()).arg(g_total_bytes.load());
    appendLog(summary, 1); // 1 = Green/Success Color

    // 5. 清理动画效果
    if (stopBtnAnim) {
        stopBtnAnim->stop();
        delete stopBtnAnim;
        stopBtnAnim = nullptr;
    }
    if (stopBtnEffect) {
        ui->btnPktAddStartTask->setGraphicsEffect(nullptr);
        stopBtnEffect = nullptr;
    }
}
// 在 sender_window.cpp 中
void MainWindow::updateStats(uint64_t currSent, uint64_t currBytes) {
    // 1. 获取时间间隔
    qint64 elapsedMs = rateTimer.elapsed();

    // 过滤过短的更新（防止除以接近0的数）
    if (elapsedMs < UIConfig::STATS_UPDATE_MIN_INTERVAL_MS) return;

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
        updateStatsDisplay(currSent, currBytes);
        return;
    }

    // 2. 正常的差分计算
    uint64_t diffSent = (currSent >= lastTotalSent) ? (currSent - lastTotalSent) : 0;
    uint64_t diffBytes = (currBytes >= lastTotalBytes) ? (currBytes - lastTotalBytes) : 0;

    lastTotalSent = currSent;
    lastTotalBytes = currBytes;

    double pps = (double)diffSent * UIConfig::MILLISECONDS_PER_SECOND / elapsedMs;
    double currentBytesPerSec = (double)diffBytes * UIConfig::MILLISECONDS_PER_SECOND / elapsedMs;

    // 3. 更新统计显示
    updateStatsDisplay(currSent, currBytes);

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
    if (m_rawByteHistory.size() > UIConfig::CHART_TIME_RANGE) m_rawByteHistory.removeFirst();

    double winMaxBps = 0;
    for (double v : m_rawByteHistory)
        if (v > winMaxBps) winMaxBps = v;

    QString unitStr = "B/s";
    double divisor = 1.0;
    constexpr double GB_BYTES = 1024.0 * 1024.0 * 1024.0;
    constexpr double MB_BYTES = 1024.0 * 1024.0;
    constexpr double KB_BYTES = 1024.0;
    if (winMaxBps >= GB_BYTES) {
        unitStr = "GB/s";
        divisor = GB_BYTES;
    } else if (winMaxBps >= MB_BYTES) {
        unitStr = "MB/s";
        divisor = MB_BYTES;
    } else if (winMaxBps >= KB_BYTES) {
        unitStr = "KB/s";
        divisor = KB_BYTES;
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
    if (scaledMax < UIConfig::CHART_MIN_SCALE_VALUE) scaledMax = UIConfig::CHART_MIN_SCALE_VALUE;
    axisY_BW->setRange(0, scaledMax * 1.2);

    if (m_chartTimeX > UIConfig::CHART_TIME_RANGE) {
        axisX_PPS->setRange(m_chartTimeX - UIConfig::CHART_TIME_RANGE, m_chartTimeX);
        axisX_BW->setRange(m_chartTimeX - UIConfig::CHART_TIME_RANGE, m_chartTimeX);
    } else {
        axisX_PPS->setRange(0, UIConfig::CHART_TIME_RANGE);
        axisX_BW->setRange(0, UIConfig::CHART_TIME_RANGE);
    }
}
// ============================================================================
// 加载配置 (启动时恢复界面状态)
// ============================================================================
void MainWindow::loadConfig() {
    m_isLoadingConfig = true; // [新增] 设置加载标志
    QSettings settings("PacketStorm", "SenderConfig");
    
    // --- 1. 加载历史记录 (原本在 loadHistory/loadMacHistory 中) ---
    // IP 历史
    QStringList ipHistory = settings.value("history/dst_ip").toStringList();
    ui->editDstIp->clear();
    if (!ipHistory.isEmpty()) {
        ui->editDstIp->addItems(ipHistory);
        ui->editDstIp->setCurrentIndex(0);
    }
    
    // MAC 历史
    QStringList macHistory = settings.value("history/dst_mac").toStringList();
    QComboBox* macCombo = qobject_cast<QComboBox*>(ui->editDstMac);
    if (macCombo) {
        macCombo->clear();
        if (!macHistory.isEmpty()) {
            macCombo->addItems(macHistory);
        }
    }

    // --- 2. 恢复主窗口几何与分割条状态 ---
    if (settings.contains("window/geometry")) {
        restoreGeometry(settings.value("window/geometry").toByteArray());
    }

    // 2. 恢复底部三栏比例 (Bottom Horizontal)
    if (ui->splitterBottom) {
        if (settings.contains("window/splitter_bottom_state")) {
            ui->splitterBottom->restoreState(settings.value("window/splitter_bottom_state").toByteArray());
        } else {
            // 默认比例：日志 : 表格 : Hex
            ui->splitterBottom->setSizes(QList<int>()
                                  << UIConfig::SPLITTER_BOTTOM_LOG_WIDTH << UIConfig::SPLITTER_BOTTOM_TABLE_WIDTH
                                  << UIConfig::SPLITTER_BOTTOM_HEX_WIDTH);
        }
    }

    // 3. 恢复主垂直分割 (Top vs Bottom)
    if (ui->splitterMainVertical) {
        if (settings.contains("window/splitter_main_vert_state")) {
            ui->splitterMainVertical->restoreState(settings.value("window/splitter_main_vert_state").toByteArray());
        } else {
            // 默认高度比例：Top : Bottom
            ui->splitterMainVertical->setSizes(QList<int>() << UIConfig::SPLITTER_MAIN_TOP_HEIGHT
                                                            << UIConfig::SPLITTER_MAIN_BOTTOM_HEIGHT);
        }
    }

    // 4. 恢复顶部水平分割 (PktSender : OsSender : TaskManager : Monitor)
    if (ui->splitterTopHorizontal) {
        if (settings.contains("window/splitter_top_horz_state")) {
            ui->splitterTopHorizontal->restoreState(settings.value("window/splitter_top_horz_state").toByteArray());
        } else {
            // 默认宽度比例：1 : 1 : 1 : 1.5
            ui->splitterTopHorizontal->setSizes(QList<int>() << 300 << 300 << 300 << 450);
        }
    }

    // 5. 恢复主流量表列宽
    if (m_packetTableView && settings.contains("window/table_column_widths")) {
        QList<int> widths = settings.value("window/table_column_widths").value<QList<int>>();
        for (int i = 0; i < widths.size() && i < 7; ++i) {
            m_packetTableView->setColumnWidth(i, widths[i]);
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
    ui->comboInterfaceTx->blockSignals(true); // [修复] 暂时断开信号连接，避免触发onInterfaceSelectionChanged()导致配置被重置
    if (idx != -1 && idx < ui->comboInterfaceTx->count()) {
        ui->comboInterfaceTx->setCurrentIndex(idx);
    } else if (ui->comboInterfaceTx->count() > 0) {
        ui->comboInterfaceTx->setCurrentIndex(0);
    }
    ui->comboInterfaceTx->blockSignals(false); // [修复] 恢复信号连接
    
    // 手动调用一次，以更新源MAC和IP显示，但不触发saveConfig
    onInterfaceSelectionChanged(ui->comboInterfaceTx->currentIndex());

    // 加载地址信息（简化：直接使用value()，如果不存在则使用空字符串，UI会保持默认值）
    ui->editSrcMac->setText(settings.value("config/src_mac", "").toString());
    
    // dst_mac 的恢复逻辑：优先使用保存的值，如果为空则尝试历史记录
    if (macCombo) {
        QString lastMac = settings.value("config/dst_mac", "").toString();
        if (!lastMac.isEmpty()) {
            macCombo->setEditText(lastMac);
        } else {
            // 如果保存的值为空，尝试从历史记录获取
            QStringList macHistory = settings.value("history/dst_mac").toStringList();
            if (!macHistory.isEmpty()) {
                macCombo->setEditText(macHistory.first());
            }
        }
    }
    
    ui->editSrcIp->setText(settings.value("config/src_ip", "").toString());
    QString currentDstIp = settings.value("config/dst_ip_val", "").toString();
    if (!currentDstIp.isEmpty()) {
        ui->editDstIp->setEditText(currentDstIp);
    }

    // [修改核心] 加载协议类型 (0=ICMP, 1=UDP, 2=TCP, 3=DNS, 4=ARP)
    // [修复] 暂时断开信号连接，避免触发onProtoToggled()导致配置被重置
    ui->rbIcmp->blockSignals(true);
    ui->rbUdp->blockSignals(true);
    ui->rbTcp->blockSignals(true);
    ui->rbDns->blockSignals(true);
    ui->rbArp->blockSignals(true);
    
    // 简化：直接使用value()，默认值为0（ICMP）
    int proto = settings.value("config/protocol", 0).toInt();
    
    // [调试] 输出加载的协议类型（仅在Debug模式下）
    #ifdef QT_DEBUG
    qDebug() << "Loading protocol:" << proto;
    #endif
    
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
            break;
    }
    
    // 加载 TCP 标志位（在恢复信号连接之前，避免触发onProtoToggled()重置配置）
    // 简化：直接使用value()，默认值为false
    ui->chkSyn->setChecked(settings.value("config/tcp_syn", false).toBool());
    ui->chkAck->setChecked(settings.value("config/tcp_ack", false).toBool());
    ui->chkPsh->setChecked(settings.value("config/tcp_psh", false).toBool());
    ui->chkFin->setChecked(settings.value("config/tcp_fin", false).toBool());
    ui->chkRst->setChecked(settings.value("config/tcp_rst", false).toBool());
    
    // [修复] 恢复信号连接（在所有配置加载完成后）
    ui->rbIcmp->blockSignals(false);
    ui->rbUdp->blockSignals(false);
    ui->rbTcp->blockSignals(false);
    ui->rbDns->blockSignals(false);
    ui->rbArp->blockSignals(false);

    // 加载载荷模式
    // [修复] 暂时断开信号连接，避免触发onPayloadModeChanged()导致配置被重置
    ui->rbPayRandom->blockSignals(true);
    ui->rbPayFixed->blockSignals(true);
    ui->rbPayCustom->blockSignals(true);
    
    // 简化：直接使用value()，默认值为0（Random）
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
    
    // 简化：直接使用value()，提供合理的默认值
    ui->spinPktLen->setValue(settings.value("config/payload_len", 64).toInt());
    ui->spinFixVal->setValue(settings.value("config/fixed_val", 0).toInt());
    ui->editCustomData->setText(settings.value("config/custom_data", "").toString());
    
    // [修复] 恢复信号连接（在所有参数加载完成后）
    ui->rbPayRandom->blockSignals(false);
    ui->rbPayFixed->blockSignals(false);
    ui->rbPayCustom->blockSignals(false);

    // 加载其他参数（端口、间隔等）
    // 简化：直接使用value()，提供合理的默认值
    #ifdef QT_DEBUG
    qDebug() << "Loading parameters...";
    #endif
    
    // 使用UIConfig中的默认值
    ui->spinInterval->setValue(settings.value("config/interval", UIConfig::DEFAULT_INTERVAL_US).toInt());
    ui->spinSrcPort->setValue(settings.value("config/src_port", 10086).toInt());
    ui->spinDstPort->setValue(settings.value("config/dst_port", 10086).toInt());
    ui->editDomain->setText(settings.value("config/domain", "www.google.com").toString());
    
    #ifdef QT_DEBUG
    qDebug() << "Loaded - interval:" << ui->spinInterval->value()
             << "src_port:" << ui->spinSrcPort->value()
             << "dst_port:" << ui->spinDstPort->value();
    #endif

    // --- 加载右侧 OS Stack Sender 配置 ---
    // 简化：直接使用value()，提供合理的默认值

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
    
    // [新增] 恢复 Connect Flood 选项和随机化参数
    ui->chkConnectFlood->setChecked(settings.value("sock_config/is_connect_only", false).toBool());
    ui->chkSockRandPort->setChecked(settings.value("sock_config/random_src_port", false).toBool());
    ui->chkSockRandMac->setChecked(settings.value("sock_config/random_src_mac", false).toBool());
    ui->chkSockRandIp->setChecked(settings.value("sock_config/random_src_ip", false).toBool());
    ui->chkSockRandSeq->setChecked(settings.value("sock_config/random_seq", false).toBool());
    ui->spinSockSPort->setValue(settings.value("sock_config/source_port", 0).toInt());

    ui->chkConnectFlood->setVisible(!ui->rbSockUdp->isChecked()); // 仅在非 UDP 时显示
    ui->sockRandomContainer->setVisible(!ui->rbSockUdp->isChecked() && ui->chkConnectFlood->isChecked());

    // Payload Size
    ui->spinSockLen->setValue(settings.value("sock_config/payload_len", 60000).toInt());

    // Interval
    ui->spinSockInt->setValue(settings.value("sock_config/interval", UIConfig::DEFAULT_SOCKET_INTERVAL_US).toInt());

    // ========================================================================
    // 应用已加载的配置到UI（在所有配置值加载完成后）
    // ========================================================================
    
    // 1. 更新UI显示状态（协议切换、载荷模式切换等）
    // 注意：这些函数可能会重置某些配置值，所以需要在之后再次恢复
    onProtoToggled();
    onPayloadModeChanged();
    
    // 2. 恢复参数部分（端口、间隔等）
    // 确保在调用onProtoToggled()和onPayloadModeChanged()之后，parameters的值仍然正确
    // 简化：直接使用value()，提供合理的默认值
    #ifdef QT_DEBUG
    qDebug() << "Restoring parameters after UI updates...";
    #endif
    
    ui->spinInterval->setValue(settings.value("config/interval", UIConfig::DEFAULT_INTERVAL_US).toInt());
    ui->spinSrcPort->setValue(settings.value("config/src_port", 10086).toInt());
    ui->spinDstPort->setValue(settings.value("config/dst_port", 10086).toInt());
    
    #ifdef QT_DEBUG
    qDebug() << "Restored - interval:" << ui->spinInterval->value()
             << "src_port:" << ui->spinSrcPort->value()
             << "dst_port:" << ui->spinDstPort->value();
    #endif
    
    // 5. 更新UI显示（在恢复所有配置值之后）
    // 触发spinInterval的valueChanged信号以更新PPS标签显示
    emit ui->spinInterval->valueChanged(ui->spinInterval->value());
    
    // 6. 强制更新所有控件的显示，确保值被正确显示
    ui->spinInterval->update();
    ui->spinSrcPort->update();
    ui->spinDstPort->update();
    
    // [调试] 输出最终值确认（仅在Debug模式下）
    #ifdef QT_DEBUG
    qDebug() << "Final values - interval:" << ui->spinInterval->value()
             << "src_port:" << ui->spinSrcPort->value()
             << "dst_port:" << ui->spinDstPort->value();
    #endif

    m_isLoadingConfig = false; // [新增] 加载完成，清除标志
}

// ============================================================================
// 保存配置 (关闭窗口或点击开始发送时调用)
// ============================================================================
void MainWindow::saveConfig() {
    QSettings settings("PacketStorm", "SenderConfig");

    // --- 1. 更新并保存历史记录 (IP 和 MAC) ---
    // IP 历史
    QString currentIp = ui->editDstIp->currentText();
    if (!currentIp.isEmpty()) {
        QStringList ipHistory = settings.value("history/dst_ip").toStringList();
        ipHistory.removeAll(currentIp);
        ipHistory.insert(0, currentIp);
        while (ipHistory.size() > UIConfig::MAX_HISTORY_ITEMS) ipHistory.removeLast();
        settings.setValue("history/dst_ip", ipHistory);
        
        // 刷新 UI 下拉列表
        ui->editDstIp->blockSignals(true);
        ui->editDstIp->clear();
        ui->editDstIp->addItems(ipHistory);
        ui->editDstIp->setEditText(currentIp);
        ui->editDstIp->blockSignals(false);
    }

    // MAC 历史
    QComboBox* macCombo = qobject_cast<QComboBox*>(ui->editDstMac);
    QString currentMac = macCombo ? macCombo->currentText() : "";
    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    if (!currentMac.isEmpty() && macRegex.match(currentMac).hasMatch()) {
        QStringList macHistory = settings.value("history/dst_mac").toStringList();
        macHistory.removeAll(currentMac);
        macHistory.insert(0, currentMac);
        while (macHistory.size() > UIConfig::MAX_HISTORY_ITEMS) macHistory.removeLast();
        settings.setValue("history/dst_mac", macHistory);
        
        // 刷新 UI 下拉列表
        if (macCombo) {
            macCombo->blockSignals(true);
            macCombo->clear();
            macCombo->addItems(macHistory);
            macCombo->setEditText(currentMac);
            macCombo->blockSignals(false);
        }
    }

    settings.setValue("window/geometry", saveGeometry());

    // 1. 保存底部三栏 (Log/Table/Hex) 的比例
    if (ui->splitterBottom) {
        settings.setValue("window/splitter_bottom_state", ui->splitterBottom->saveState());
    }

    // 2. 保存主垂直分割 (Top/Bottom) 的比例
    if (ui->splitterMainVertical) {
        settings.setValue("window/splitter_main_vert_state", ui->splitterMainVertical->saveState());
    }

    // 3. 保存顶部水平分割 (Config/Monitor/OS/TaskManager) 的比例
    if (ui->splitterTopHorizontal) {
        settings.setValue("window/splitter_top_horz_state", ui->splitterTopHorizontal->saveState());
    }

    // 4. 保存主流量表 (tablePackets) 的列宽
    if (m_packetTableView) {
        QList<int> widths;
        for (int i = 0; i < 7; ++i) { // PacketTableModel 有 7 列
            widths << m_packetTableView->columnWidth(i);
        }
        settings.setValue("window/table_column_widths", QVariant::fromValue(widths));
    }

    // 保存 WinPcap 模块配置
    settings.setValue("config/interface_name", ui->comboInterfaceTx->currentData().toString());
    settings.setValue("config/interface_index", ui->comboInterfaceTx->currentIndex());
    settings.setValue("config/src_mac", ui->editSrcMac->text());
    // dst_mac 的当前值在 saveMacHistory() 中保存，这里也保存一份作为最后一次的值
    // editDstMac 现在是 QComboBox，使用 currentText()
    QString dstMac = qobject_cast<QComboBox*>(ui->editDstMac)->currentText();
    settings.setValue("config/dst_mac", dstMac);
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
    
    // [调试] 输出保存时的实际协议状态（仅在Debug模式下）
    #ifdef QT_DEBUG
    qDebug() << "Saving protocol:" << proto 
             << "UDP:" << ui->rbUdp->isChecked()
             << "TCP:" << ui->rbTcp->isChecked()
             << "ICMP:" << ui->rbIcmp->isChecked();
    #endif

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
    
    // [调试] 输出保存时的实际参数值（仅在Debug模式下）
    #ifdef QT_DEBUG
    qDebug() << "Saving parameters - interval:" << ui->spinInterval->value()
             << "src_port:" << ui->spinSrcPort->value()
             << "dst_port:" << ui->spinDstPort->value();
    #endif

    // --- 保存右侧 OS Stack Sender 配置 ---

    settings.setValue("sock_config/source_iface", ui->comboSockSrc->currentData().toString());
    settings.setValue("sock_config/target_ip", ui->editSockIp->text());
    settings.setValue("sock_config/target_port", ui->spinSockPort->value());
    settings.setValue("sock_config/is_udp", ui->rbSockUdp->isChecked());
    
    // [新增] 保存 Connect Flood 选项和随机化参数
    settings.setValue("sock_config/is_connect_only", ui->chkConnectFlood->isChecked());
    settings.setValue("sock_config/random_src_port", ui->chkSockRandPort->isChecked());
    settings.setValue("sock_config/random_src_mac", ui->chkSockRandMac->isChecked());
    settings.setValue("sock_config/random_src_ip", ui->chkSockRandIp->isChecked());
    settings.setValue("sock_config/random_seq", ui->chkSockRandSeq->isChecked());
    settings.setValue("sock_config/source_port", ui->spinSockSPort->value());
    
    settings.setValue("sock_config/payload_len", ui->spinSockLen->value());
    settings.setValue("sock_config/interval", ui->spinSockInt->value());
    
    // [修复] 确保所有配置都被同步保存到磁盘
    settings.sync();
    
    // [调试] 验证保存的配置（仅在Debug模式下）
    #ifdef QT_DEBUG
    int savedProto = settings.value("config/protocol", -1).toInt();
    int savedSrcPort = settings.value("config/src_port", -1).toInt();
    int savedDstPort = settings.value("config/dst_port", -1).toInt();
    qDebug() << "Config saved successfully - protocol:" << savedProto 
             << "src_port:" << savedSrcPort 
             << "dst_port:" << savedDstPort;
    #endif
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

    // 2. 状态栏反馈（仅在日志消息时临时显示，tooltip会覆盖它）
    // 注意：现在状态栏主要用于显示鼠标所在位置控件的tooltip
    // 日志消息只在没有tooltip时显示3秒
    if (this->statusBar()) {
        // 如果当前没有tooltip显示，则显示日志消息
        if (this->statusBar()->currentMessage().isEmpty()) {
            this->statusBar()->showMessage(msg, 3000);
        }
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
    if (level == 2 && m_packetTableView) {
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

    // 4. 设置样式表 (已在 .ui 文件中统一管理)
    ui->tableHex->setObjectName("tableHex");

    // 5. 安装代理和过滤器 (保持不变)
    m_hexDelegate = new HexRenderDelegate(this);
    ui->tableHex->setItemDelegate(m_hexDelegate);
    ui->tableHex->setMouseTracking(true);
    ui->tableHex->viewport()->installEventFilter(this);
}

// ============================================================================
// [优化] Hex表格增量更新：如果行数相同，只更新内容，不重建表格
// ============================================================================
void MainWindow::updateHexTable(const QByteArray& data) {
    int len = data.size();
    int rowCount = (len + 15) / 16;
    int currentRowCount = ui->tableHex->rowCount();

    // 如果行数相同，使用增量更新（只更新内容，不重建表格）
    if (currentRowCount == rowCount && rowCount > 0) {
        updateHexTableContent(data);
        return;
    }

    // 行数不同，需要重建表格
    ui->tableHex->setRowCount(0); // 清空

    const unsigned char* p = (const unsigned char*)data.constData();

    // 强制行高，使视图紧凑
    ui->tableHex->verticalHeader()->setDefaultSectionSize(20);

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

// ============================================================================
// [新增] 增量更新Hex表格内容（不重建表格，只更新现有单元格）
// ============================================================================
void MainWindow::updateHexTableContent(const QByteArray& data) {
    int len = data.size();
    const unsigned char* p = (const unsigned char*)data.constData();

    for (int i = 0; i < len; i += 16) {
        int row = i / 16;

        // --- Column 0: Offset（通常不变，但为了完整性也更新）---
        QString offsetStr = QString("%1").arg(i, 4, 16, QChar('0')).toUpper();
        QTableWidgetItem* offsetItem = ui->tableHex->item(row, 0);
        if (offsetItem) {
            offsetItem->setText(offsetStr);
        } else {
            ui->tableHex->setItem(row, 0, new QTableWidgetItem(offsetStr));
        }

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

        // 更新或创建 Hex 列
        QTableWidgetItem* hexItem = ui->tableHex->item(row, 1);
        if (hexItem) {
            hexItem->setText(hexStr);
        } else {
            ui->tableHex->setItem(row, 1, new QTableWidgetItem(hexStr));
        }

        // 更新或创建 ASCII 列
        QTableWidgetItem* asciiItem = ui->tableHex->item(row, 2);
        if (asciiItem) {
            asciiItem->setText(asciiStr);
        } else {
            ui->tableHex->setItem(row, 2, new QTableWidgetItem(asciiStr));
        }
    }
}

bool MainWindow::eventFilter(QObject* watched, QEvent* event) {
    // [新增] 为任务管理器的三个控制按钮实现悬停发光动画
    if (QPushButton* btn = qobject_cast<QPushButton*>(watched)) {
        QString text = btn->text();
        if (text == "Start All" || text == "Stop All" || text == "Clear All") {
            if (event->type() == QEvent::Enter) {
                QGraphicsDropShadowEffect* glow = new QGraphicsDropShadowEffect(btn);
                glow->setOffset(0, 0);
                glow->setBlurRadius(15);
                
                // 根据按钮文字设置发光颜色
                if (text == "Start All") glow->setColor(QColor("#00e676"));
                else if (text == "Stop All") glow->setColor(QColor("#ff1744"));
                else glow->setColor(QColor("#00f0ff"));
                
                btn->setGraphicsEffect(glow);
                
                // 属性动画让光晕跳动
                QPropertyAnimation* anim = new QPropertyAnimation(glow, "blurRadius");
                anim->setDuration(400);
                anim->setStartValue(10);
                anim->setEndValue(25);
                anim->setEasingCurve(QEasingCurve::OutQuad);
                anim->start(QAbstractAnimation::DeleteWhenStopped);
            } else if (event->type() == QEvent::Leave) {
                btn->setGraphicsEffect(nullptr);
            }
        }
    }

    // [新增] 拦截ToolTip事件，阻止默认弹窗显示，但保留状态栏显示
    if (event->type() == QEvent::ToolTip) {
        QWidget* widget = qobject_cast<QWidget*>(watched);
        if (widget && statusBar()) {
            QString tooltip = widget->toolTip();
            if (!tooltip.isEmpty()) {
                statusBar()->showMessage(tooltip);
            } else {
                // 如果没有tooltip，尝试显示对象名称
                QString objName = widget->objectName();
                if (!objName.isEmpty()) {
                    statusBar()->showMessage(objName);
                } else {
                    statusBar()->clearMessage();
                }
            }
        }
        return true; // 阻止默认的tooltip弹窗
    }

    // 状态栏显示鼠标所在位置控件的tooltip（Enter事件）
    if (event->type() == QEvent::Enter) {
        QWidget* widget = qobject_cast<QWidget*>(watched);
        if (widget && statusBar()) {
            QString tooltip = widget->toolTip();
            if (!tooltip.isEmpty()) {
                statusBar()->showMessage(tooltip);
            } else {
                // 如果没有tooltip，尝试显示对象名称
                QString objName = widget->objectName();
                if (!objName.isEmpty()) {
                    statusBar()->showMessage(objName);
                } else {
                    statusBar()->clearMessage();
                }
            }
        }
    } else if (event->type() == QEvent::Leave) {
        // 鼠标离开时清除状态栏消息（但保留Hex表格的处理）
        if (watched != ui->tableHex->viewport() && statusBar()) {
            statusBar()->clearMessage();
        }
    }

    // Hex 表格鼠标悬停高亮
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

// ============================================================================
// [新增] 设置系统资源监控
// ============================================================================
void MainWindow::setupResourceMonitor() {
    // 创建资源监控对象
    m_resourceMonitor = new SystemResourceMonitor(this);

    // 创建容器
    m_resourceContainer = new QWidget();
    m_resourceContainer->setObjectName("resourceContainer");
    QHBoxLayout* resourceLayout = new QHBoxLayout(m_resourceContainer);
    resourceLayout->setContentsMargins(5, 8, 5, 8);
    resourceLayout->setSpacing(5); // 减小间距
    resourceLayout->addStretch();

    // 创建 CPU 监控组件
    m_cpuWidget = new CircularProgressWidget(m_resourceContainer);
    m_cpuWidget->setLabel("CPU");
    m_cpuWidget->setUnit("%");
    m_cpuWidget->setColor(QColor("#00e676")); 
    resourceLayout->addWidget(m_cpuWidget);

    // 创建内存监控组件
    m_memoryWidget = new CircularProgressWidget(m_resourceContainer);
    m_memoryWidget->setLabel("RAM"); // 缩写以节省空间
    m_memoryWidget->setUnit("%");
    m_memoryWidget->setColor(QColor("#d500f9")); 
    resourceLayout->addWidget(m_memoryWidget);

    // 创建上传速率监控组件
    m_uploadWidget = new CircularProgressWidget(m_resourceContainer);
    m_uploadWidget->setLabel("Up");
    m_uploadWidget->setUnit("MB/s");
    m_uploadWidget->setColor(QColor("#ff6d00")); 
    resourceLayout->addWidget(m_uploadWidget);

    // 创建下载速率监控组件
    m_downloadWidget = new CircularProgressWidget(m_resourceContainer);
    m_downloadWidget->setLabel("Down");
    m_downloadWidget->setUnit("MB/s");
    m_downloadWidget->setColor(QColor("#00bcd4")); 
    resourceLayout->addWidget(m_downloadWidget);

    resourceLayout->addSpacing(10);

    // 创建已发送统计显示容器
    QWidget* statsContainer = new QWidget(m_resourceContainer);
    QVBoxLayout* statsLayout = new QVBoxLayout(statsContainer);
    statsLayout->setContentsMargins(10, 0, 10, 0);
    statsLayout->setSpacing(2);

    QLabel* statsTitle = new QLabel("TOTAL SENT", statsContainer);
    statsTitle->setObjectName("lblStatsTitle");
    statsTitle->setAlignment(Qt::AlignLeft | Qt::AlignBottom);
    statsLayout->addWidget(statsTitle);

    m_packetsLabel = new QLabel("0 pkts", statsContainer);
    m_packetsLabel->setObjectName("lblPacketsTotal");
    m_packetsLabel->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    statsLayout->addWidget(m_packetsLabel);

    m_bytesLabel = new QLabel("0 B", statsContainer);
    m_bytesLabel->setObjectName("lblBytesTotal");
    m_bytesLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    statsLayout->addWidget(m_bytesLabel);

    statsContainer->setFixedWidth(120); 
    resourceLayout->addWidget(statsContainer);

    resourceLayout->addStretch();

    // 连接信号
    connect(m_resourceMonitor, &SystemResourceMonitor::resourceUpdated, this, &MainWindow::updateResourceDisplay,
            Qt::QueuedConnection);
    connect(m_resourceMonitor, &SystemResourceMonitor::networkStatsUpdated, this, &MainWindow::updateNetworkDisplay,
            Qt::QueuedConnection);
    connect(m_resourceMonitor, &SystemResourceMonitor::logMessage, this, &MainWindow::appendLog, Qt::QueuedConnection);
}

// ============================================================================
// [新增] 递归为所有子控件安装事件过滤器
// ============================================================================
void MainWindow::installEventFilterRecursive(QWidget* widget) {
    if (widget) {
        widget->installEventFilter(this);
        for (QObject* child : widget->children()) {
            QWidget* childWidget = qobject_cast<QWidget*>(child);
            if (childWidget) {
                installEventFilterRecursive(childWidget);
            }
        }
    }
}

// ============================================================================
// [新增] 为所有控件设置tooltip
// ============================================================================
void MainWindow::setupTooltips() {
    // 网卡选择
    if (ui->comboInterfaceTx) {
        ui->comboInterfaceTx->setToolTip("选择用于发送数据包的网络接口（网卡）");
    }

    // 地址协议组
    if (ui->editSrcMac) {
        ui->editSrcMac->setToolTip("源MAC地址（发送方MAC地址），格式：AA:BB:CC:DD:EE:FF");
    }
    if (ui->editDstMac) {
        QComboBox* dstMacCombo = qobject_cast<QComboBox*>(ui->editDstMac);
        if (dstMacCombo) {
            dstMacCombo->setToolTip("目标MAC地址（接收方MAC地址），格式：AA:BB:CC:DD:EE:FF\n"
                                    "FF:FF:FF:FF:FF:FF 表示广播地址");
        }
    }
    if (ui->btnGetMac) {
        ui->btnGetMac->setToolTip("通过ARP协议自动解析目标IP对应的MAC地址");
    }
    if (ui->editSrcIp) {
        ui->editSrcIp->setToolTip("源IP地址（发送方IP地址），格式：192.168.1.1");
    }
    if (ui->editDstIp) {
        QComboBox* dstIpCombo = qobject_cast<QComboBox*>(ui->editDstIp);
        if (dstIpCombo) {
            dstIpCombo->setToolTip("目标IP地址（接收方IP地址），格式：192.168.1.1\n"
                                   "支持历史记录，点击下拉箭头查看");
        }
    }

    // 协议选择
    if (ui->rbIcmp) {
        ui->rbIcmp->setToolTip("Internet控制消息协议（ICMP）\n"
                               "用于ping、traceroute等网络诊断工具");
    }
    if (ui->rbUdp) {
        ui->rbUdp->setToolTip("用户数据报协议（UDP）\n"
                              "无连接、不可靠的传输协议，适用于实时应用");
    }
    if (ui->rbTcp) {
        ui->rbTcp->setToolTip("传输控制协议（TCP）\n"
                              "面向连接、可靠的传输协议，需要设置TCP标志");
    }
    if (ui->rbDns) {
        ui->rbDns->setToolTip("域名系统协议（DNS）\n"
                              "用于域名解析查询");
    }
    if (ui->rbArp) {
        ui->rbArp->setToolTip("地址解析协议（ARP）\n"
                              "用于将IP地址解析为MAC地址");
    }

    // TCP标志
    if (ui->chkSyn) {
        ui->chkSyn->setToolTip("SYN标志：同步序列号，用于建立TCP连接");
    }
    if (ui->chkAck) {
        ui->chkAck->setToolTip("ACK标志：确认标志，表示确认号有效");
    }
    if (ui->chkPsh) {
        ui->chkPsh->setToolTip("PSH标志：推送标志，要求立即将数据推送给应用层");
    }
    if (ui->chkFin) {
        ui->chkFin->setToolTip("FIN标志：结束标志，用于关闭TCP连接");
    }
    if (ui->chkRst) {
        ui->chkRst->setToolTip("RST标志：重置标志，用于重置异常连接");
    }

    // DNS域名
    if (ui->editDomain) {
        ui->editDomain->setToolTip("DNS查询的域名（仅在DNS协议模式下有效）\n"
                                   "例如：www.google.com");
    }

    // 载荷选项
    if (ui->rbPayRandom) {
        ui->rbPayRandom->setToolTip("随机载荷：数据包载荷使用随机字节填充");
    }
    if (ui->rbPayFixed) {
        ui->rbPayFixed->setToolTip("固定字节载荷：数据包载荷使用指定的固定字节值填充");
    }
    if (ui->rbPayCustom) {
        ui->rbPayCustom->setToolTip("自定义载荷：数据包载荷使用自定义文本内容");
    }
    if (ui->spinPktLen) {
        ui->spinPktLen->setToolTip("数据包载荷长度（字节）\n"
                                   "范围：1-65500字节\n"
                                   "注意：实际数据包大小 = 以太网头(14) + IP头(20) + 协议头 + 载荷长度");
    }
    if (ui->spinFixVal) {
        ui->spinFixVal->setToolTip("固定字节值（十六进制）\n"
                                   "仅在固定字节载荷模式下有效\n"
                                   "范围：0x00-0xFF");
    }
    if (ui->editCustomData) {
        ui->editCustomData->setToolTip("自定义载荷内容（文本）\n"
                                       "仅在自定义载荷模式下有效\n"
                                       "输入的内容将作为数据包的载荷部分");
    }

    // 发送参数
    if (ui->spinInterval) {
        ui->spinInterval->setToolTip("发送间隔（微秒，µs）\n"
                                     "1000 µs = 1 ms\n"
                                     "10000 µs = 10 ms\n"
                                     "设置为 0 表示全速发送（无延迟）");
    }
    if (lblTargetPPS) {
        lblTargetPPS->setToolTip("根据发送间隔计算的目标发送速率（包/秒）\n"
                                 "计算公式：1,000,000 / 间隔(µs) = 包/秒");
    }
    if (ui->spinSrcPort) {
        ui->spinSrcPort->setToolTip("源端口号（仅在UDP/TCP协议模式下有效）\n"
                                    "范围：0-65535");
    }
    if (ui->spinDstPort) {
        ui->spinDstPort->setToolTip("目标端口号（仅在UDP/TCP协议模式下有效）\n"
                                    "范围：0-65535");
    }

    // 按钮
    if (ui->btnPktAddTask) {
        ui->btnPktAddTask->setToolTip("添加发送任务但不启动\n"
                                     "点击后将在任务管理器中创建一个新的停止状态任务");
    }
    if (ui->btnPktAddStartTask) {
        ui->btnPktAddStartTask->setToolTip("添加并立即开始发送任务\n"
                                    "点击后将创建一个新任务并立即启动发送线程");
    }

    // Socket发送模块
    if (ui->comboSockSrc) {
        ui->comboSockSrc->setToolTip("选择源网络接口（用于Socket发送）\n"
                                     "系统会自动查找该接口的IP地址");
    }
    if (ui->editSockIp) {
        ui->editSockIp->setToolTip("目标IP地址（Socket发送模式）\n"
                                   "格式：192.168.1.1");
    }
    if (ui->spinSockPort) {
        ui->spinSockPort->setToolTip("目标端口号（Socket发送模式）\n"
                                     "范围：0-65535");
    }
    if (ui->rbSockUdp) {
        ui->rbSockUdp->setToolTip("使用UDP协议发送（Socket模式）\n"
                                  "无连接、不可靠的传输");
    }
    if (ui->rbSockTcp) {
        ui->rbSockTcp->setToolTip("使用TCP协议发送（Socket模式）\n"
                                  "面向连接、可靠的传输");
    }
    if (ui->spinSockLen) {
        ui->spinSockLen->setToolTip("Socket发送的载荷大小（字节）\n"
                                    "范围：1-65507字节（UDP最大载荷）");
    }
    if (ui->spinSockInt) {
        ui->spinSockInt->setToolTip("Socket发送间隔（微秒，µs）\n"
                                    "控制Socket模式下的发送速率");
    }
    if (ui->btnSockAddTask) {
        ui->btnSockAddTask->setToolTip("添加Socket发送任务\n"
                                     "点击后将在任务管理器中创建一个新的停止状态任务");
    }
    if (ui->btnSockAddStartTask) {
        ui->btnSockAddStartTask->setToolTip("添加并开始Socket发送\n"
                                     "点击后将创建一个新任务并立即开始发送");
    }

    // 图表和监控
    if (ui->grpChart) {
        ui->grpChart->setToolTip("流量监控图表\n"
                                 "显示实时发送速率（PPS）和带宽（MB/s）趋势");
    }

    // 数据包表格
    if (m_packetTableView) {
        m_packetTableView->setToolTip("已发送数据包列表\n"
                                      "显示每批发送的最后一个数据包的详细信息\n"
                                      "点击行可查看数据包的十六进制内容");
    }

    // Hex视图
    if (ui->tableHex) {
        ui->tableHex->setToolTip("数据包十六进制视图\n"
                                 "显示选中数据包的完整十六进制内容\n"
                                 "左侧：偏移量，中间：十六进制，右侧：ASCII字符");
    }

    // 日志窗口
    if (ui->txtLog) {
        ui->txtLog->setToolTip("系统日志窗口\n"
                               "显示系统运行状态、错误信息和调试信息");
    }

    // 自动滚动
    if (ui->chkAutoScroll) {
        ui->chkAutoScroll->setToolTip("自动滚动到最新数据包\n"
                                      "启用后，新数据包会自动滚动到底部并显示");
    }

    // GroupBox工具提示
    if (ui->grpSender) {
        ui->grpSender->setToolTip("WinPcap原始数据包发送模块\n"
                                  "使用WinPcap/Npcap库直接构造和发送数据包");
    }
    if (ui->grpAddr) {
        ui->grpAddr->setToolTip("地址和协议配置\n"
                                "配置源/目标MAC地址和IP地址");
    }
    if (ui->grpParam) {
        ui->grpParam->setToolTip("协议参数配置\n"
                                 "选择协议类型和设置协议相关参数");
    }
    if (ui->grpPayload) {
        ui->grpPayload->setToolTip("数据包载荷配置\n"
                                   "设置数据包载荷的模式和内容");
    }
    if (ui->grpSocketSender) {
        ui->grpSocketSender->setToolTip("操作系统网络栈发送模块\n"
                                        "使用操作系统Socket API发送数据包\n"
                                        "支持自动分片，适用于大包发送");
    }
    if (ui->grpSockProto) {
        ui->grpSockProto->setToolTip("Socket协议选择\n"
                                     "选择UDP或TCP协议");
    }
}

// ============================================================================
// [新增] 更新资源显示
// ============================================================================
void MainWindow::updateResourceDisplay(double cpuUsage, double memoryUsage) {
    if (m_cpuWidget) {
        m_cpuWidget->setValue(cpuUsage);
    }
    if (m_memoryWidget) {
        m_memoryWidget->setValue(memoryUsage);
    }
}

// ============================================================================
// [新增] 更新网卡流量显示
// ============================================================================
void MainWindow::updateNetworkDisplay(double uploadSpeed, double downloadSpeed) {
    // 自适应单位显示：根据速度值自动选择 KB/s 或 MB/s
    // 注意：这里显示的是整个网卡的总流量（包括本应用、其他应用、系统流量、ICMP 响应等）
    // 与右下角状态栏的"Speed"不同，状态栏只统计本应用程序发送的数据包
    auto formatSpeed = [](double speedMBps) -> QPair<double, QString> {
        if (speedMBps < 0.001) {
            // 小于 0.001 MB/s，显示为 0.0 KB/s
            return QPair<double, QString>(0.0, "KB/s");
        } else if (speedMBps < 1.0) {
            // 小于 1 MB/s，转换为 KB/s 显示
            double speedKBps = speedMBps * 1024.0;
            return QPair<double, QString>(speedKBps, "KB/s");
        } else if (speedMBps < 1024.0) {
            // 1 MB/s 到 1024 MB/s，显示 MB/s
            return QPair<double, QString>(speedMBps, "MB/s");
        } else {
            // 大于等于 1024 MB/s，转换为 GB/s 显示
            double speedGBps = speedMBps / 1024.0;
            return QPair<double, QString>(speedGBps, "GB/s");
        }
    };

    if (m_uploadWidget) {
        QPair<double, QString> result = formatSpeed(uploadSpeed);
        m_uploadWidget->setUnit(result.second);
        m_uploadWidget->setValue(result.first);
    }
    if (m_downloadWidget) {
        QPair<double, QString> result = formatSpeed(downloadSpeed);
        m_downloadWidget->setUnit(result.second);
        m_downloadWidget->setValue(result.first);
    }
}

// ============================================================================
// [新增] 更新统计数据显示（已发包数量和已发送字节）
// ============================================================================
void MainWindow::updateStatsDisplay(uint64_t sent, uint64_t bytes) {
    // 格式化已发包数量（显示原始值，不缩写，带单位）
    if (m_packetsLabel) {
        QLocale loc(QLocale::English);
        // 直接显示完整数字，带千位分隔符，后面加单位
        QString packetsText = loc.toString((qulonglong)sent) + " pkts";
        m_packetsLabel->setText(packetsText);
    }

    // 格式化已发送字节
    if (m_bytesLabel) {
        QString bytesText;
        double dBytes = (double)bytes;
        if (dBytes >= 1024.0 * 1024.0 * 1024.0) {
            // 大于等于1GB，显示为X.XX GB
            double bytesGB = dBytes / (1024.0 * 1024.0 * 1024.0);
            bytesText = QString::number(bytesGB, 'f', 2) + " GB";
        } else if (dBytes >= 1024.0 * 1024.0) {
            // 大于等于1MB，显示为X.XX MB
            double bytesMB = dBytes / (1024.0 * 1024.0);
            bytesText = QString::number(bytesMB, 'f', 2) + " MB";
        } else if (dBytes >= 1024.0) {
            // 大于等于1KB，显示为X.XX KB
            double bytesKB = dBytes / 1024.0;
            bytesText = QString::number(bytesKB, 'f', 2) + " KB";
        } else {
            // 小于1KB，显示为字节数（带千位分隔符）
            QLocale loc(QLocale::English);
            bytesText = loc.toString((qulonglong)bytes) + " B";
        }
        m_bytesLabel->setText(bytesText);
    }
}
