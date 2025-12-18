#pragma once

#include <QMainWindow>
#include <QThread>
#include <QTimer>
#include <QElapsedTimer>
#include <QRegularExpression>
#include "sender_core.h"
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>
#include <QLabel>
#include <QStatusBar>
#include <QLocale>
#include <QNetworkInterface>
#include <QHostAddress>
#include <QPushButton>
#include <QSettings>
#include <QDateTime>

// =========================================================
// [修复] 显式引入具体的 Charts 头文件
// =========================================================
#include <QtCharts/QChartView>
#include <QtCharts/QSplineSeries>
#include <QtCharts/QValueAxis>
#include <QtCharts/QChart>

#include <QTableWidget>
#include <QMouseEvent>
#include "hex_delegate.h" // [新增] 引入头文件


namespace Ui {
class MainWindow;
}

// ============================================================================
// StatusDashboard 结构体
// ============================================================================
struct StatusDashboard {
    QLabel *lblCount;
    QLabel *lblBytes;
    QLabel *lblRate;

    void init(QStatusBar* bar, QWidget* parent) {
        bar->setStyleSheet(
            "QStatusBar { background: #0f121a; color: #718096; border-top: 1px solid #1c2333; }"
            "QStatusBar::item { border: none; }"
            );

        lblCount = new QLabel("Sent: 0", parent);
        lblBytes = new QLabel("Data: 0 B", parent);
        lblRate  = new QLabel("Speed: 0 pps | 0 B/s", parent);

        lblCount->setFixedWidth(150);
        lblBytes->setFixedWidth(150);
        lblRate->setFixedWidth(400);

        lblCount->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        lblBytes->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        lblRate->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        lblCount->setStyleSheet("color: #00e676; font-weight: bold; padding-right: 5px;");
        lblBytes->setStyleSheet("color: #00f0ff; font-weight: bold; padding-right: 5px;");
        lblRate->setStyleSheet("color: #FFB74D; font-weight: bold; padding-left: 10px;");

        bar->addPermanentWidget(lblCount);
        bar->addPermanentWidget(lblBytes);
        bar->addPermanentWidget(lblRate);
    }

    void updateUI(uint64_t sent, uint64_t bytes, double pps, double bps) {
        QLocale loc(QLocale::English);
        lblCount->setText("Sent: " + loc.toString((qulonglong)sent));

        QString byteStr;
        double dBytes = (double)bytes;
        if (dBytes < 1024) byteStr = QString::number(dBytes) + " B";
        else if (dBytes < 1024*1024) byteStr = QString::number(dBytes/1024.0, 'f', 1) + " KB";
        else if (dBytes < 1024*1024*1024) byteStr = QString::number(dBytes/(1024*1024.0), 'f', 2) + " MB";
        else byteStr = QString::number(dBytes/(1024*1024*1024.0), 'f', 2) + " GB";
        lblBytes->setText("Data: " + byteStr);

        QString ppsStr;
        if (pps >= 1000000) ppsStr = QString::number(pps/1000000.0, 'f', 2) + " Mpps";
        else if (pps >= 1000) ppsStr = QString::number(pps/1000.0, 'f', 1) + " kpps";
        else ppsStr = QString::number((int)pps) + " pps";

        QString bpsStr;
        if (bps >= 1024*1024*1024) bpsStr = QString::number(bps/(1024.0*1024*1024), 'f', 2) + " GB/s";
        else if (bps >= 1024*1024) bpsStr = QString::number(bps/(1024.0*1024), 'f', 2) + " MB/s";
        else if (bps >= 1024) bpsStr = QString::number(bps/1024.0, 'f', 1) + " KB/s";
        else bpsStr = QString::number((int)bps) + " B/s";

        lblRate->setText(QString("Speed: %1 | %2").arg(ppsStr).arg(bpsStr));
    }
};

// ============================================================================
// PacketWorker 类
// ============================================================================
class PacketWorker : public QObject {
    Q_OBJECT
public:
    SenderConfig config;
    QByteArray customDataBuffer;

    static void StatsCallbackProxy(uint64_t sent, uint64_t bytes) {
        if (m_instance) {
            emit m_instance->statsUpdated(sent, bytes);
        }
    }

    // [新增] Hex 代理函数
    static void HexCallbackProxy(const unsigned char* data, int len) {
        if (m_instance) {
            // 原代码：int showLen = (len > 48) ? 48 : len;
            // 修改后：直接使用 len，或者设置一个非常大的上限（如 65535）防止极个别情况崩溃
            // 但通常直接发完整包即可，因为以太网包最大也就 1500 左右

            QByteArray b((const char*)data, len);
            emit m_instance->hexUpdated(b);
        }
    }

public slots:
    void doSendWork() {
        m_instance = this;
        if (config.payload_mode == PAYLOAD_CUSTOM) {
            config.custom_data = customDataBuffer.constData();
            config.custom_data_len = customDataBuffer.length();
        } else {
            config.custom_data = nullptr;
            config.custom_data_len = 0;
        }
        config.stats_callback = &PacketWorker::StatsCallbackProxy;
        // [新增] 注册回调
        config.hex_callback = &PacketWorker::HexCallbackProxy;

        g_is_sending = true;
        start_send_mode(&config);
        m_instance = nullptr;
        emit workFinished();
    }
signals:
    void workFinished();
    void statsUpdated(uint64_t sent, uint64_t bytes);
    // [新增] 信号
    void hexUpdated(QByteArray data);

private:
    static PacketWorker* m_instance;
};
// ============================================================================
// sender_window.h -> SocketWorker 类完整定义
// ============================================================================
class SocketWorker : public QObject {
    Q_OBJECT
public:
    SocketConfig config;
    static SocketWorker* m_instance;

    // 统计数据代理
    static void StatsCallbackProxy(uint64_t sent, uint64_t bytes) {
        if (m_instance) {
            emit m_instance->statsUpdated(sent, bytes);
        }
    }

    // [新增] 日志数据代理
    static void LogCallbackProxy(const char* msg, int level) {
        if (m_instance) {
            // 将 C-Style 字符串转为 Qt 字符串并跨线程发射
            emit m_instance->logUpdated(QString::fromLocal8Bit(msg), level);
        }
    }

public slots:
    void doWork() {
        m_instance = this;

        // 注册回调函数
        config.stats_callback = &SocketWorker::StatsCallbackProxy;
        config.log_callback   = &SocketWorker::LogCallbackProxy; // [新增]

        g_is_sock_sending = true;
        start_socket_send_mode(&config);

        m_instance = nullptr;
        emit workFinished();
    }

signals:
    void workFinished();
    void statsUpdated(uint64_t sent, uint64_t bytes);

    // [新增] 日志信号
    void logUpdated(QString msg, int level);
};

// ============================================================================
// MainWindow 类
// ============================================================================
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void onStartSendClicked();
    void onStopSendClicked();
    void onProtoToggled();
    void onPayloadModeChanged();
    void updateStats(uint64_t currSent, uint64_t currBytes);
    void onInterfaceSelectionChanged(int index);
    void onGetDstMacClicked();
    void onSockStartClicked();
    void onSockStopClicked();
    void updateSockStats(uint64_t sent, uint64_t bytes);

private:
    void loadInterfaces();
    void loadHistory();
    void saveHistory(const QString &ip);
    void loadConfig();
    void saveConfig();
    void appendLog(const QString &msg, int level = 0);

    void setupChart();

    void setupTrafficTable();
    void addPacketToTable(const QByteArray& data);

    HexRenderDelegate* m_hexDelegate;

    void setupHexTableStyle();
    void updateHexTable(const QByteArray& data);

    // 简易协议解析器
    struct PacketInfo {
        QString src;
        QString dst;
        QString proto;
        QString info;
        int length;
    };
    PacketInfo parsePacket(const QByteArray& data);

    int m_packetCount = 0; // 记录包序号

    Ui::MainWindow *ui;
    QThread *workerThread;
    PacketWorker *worker;
    QPropertyAnimation *stopBtnAnim;
    QGraphicsDropShadowEffect *stopBtnEffect;
    QTimer *statsTimer;
    QElapsedTimer rateTimer;
    uint64_t lastTotalSent = 0;
    uint64_t lastTotalBytes = 0;
    StatusDashboard m_dashboard;
    QLabel *lblTargetPPS;
    QPushButton *btnGetMac;

    QList<double> m_ppsHistory;


    QList<double> m_rawByteHistory;
    // [修改] 拆分为两个图表的变量
    QChartView *viewPPS; // PPS 视图
    QChartView *viewBW;  // Bandwidth 视图

    QChart *chartPPS;
    QChart *chartBW;

    QSplineSeries *seriesPPS;
    QSplineSeries *seriesMbps;

    QValueAxis *axisX_PPS; // PPS 的时间轴
    QValueAxis *axisX_BW;  // BW 的时间轴

    QValueAxis *axisY_PPS; // PPS 的数值轴
    QValueAxis *axisY_BW;  // BW 的数值轴 (原 axisY_Mbps)

    qint64 m_chartTimeX;
    double m_maxPPS;
    double m_maxMbps;

    QThread *sockThread;
    SocketWorker *sockWorker;
};




