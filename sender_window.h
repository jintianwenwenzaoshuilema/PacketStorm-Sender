#pragma once

#include "sender_core.h"
#include <QDateTime>
#include <QElapsedTimer>
#include <QGraphicsDropShadowEffect>
#include <QHostAddress>
#include <QLabel>
#include <QLocale>
#include <QMainWindow>
#include <QNetworkInterface>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QStatusBar>
#include <QThread>
#include <QTimer>

// =========================================================
// [修复] 显式引入具体的 Charts 头文件
// =========================================================
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QSplineSeries>
#include <QtCharts/QValueAxis>

#include "hex_delegate.h"       // [新增] 引入头文件
#include "packet_table_model.h" // [MVC] 数据包表格模型
#include "resource_monitor.h"   // [新增] 系统资源监控
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QMouseEvent>
#include <QTableView>
#include <QTableWidget>

// ============================================================================
// [优化] UI 常量定义 - 消除魔法数字
// ============================================================================
namespace UIConfig {
// 数据包表格配置
constexpr int MAX_PACKET_TABLE_ROWS = 1000; // 数据包表格最大行数

// 图表配置
constexpr int CHART_TIME_RANGE = 60;            // 图表时间轴范围（秒）
constexpr int CHART_PPS_MAX_Y = 1000;           // PPS图表Y轴最大值
constexpr double CHART_PPS_DEFAULT_MAX = 100.0; // PPS图表默认最大值
constexpr double CHART_BW_DEFAULT_MAX = 10.0;   // 带宽图表默认最大值
constexpr double CHART_MIN_SCALE_VALUE = 10.0;  // 图表最小缩放值

// 历史记录配置
constexpr int MAX_HISTORY_ITEMS = 10; // 历史记录最大数量

// 布局配置
constexpr int CHART_LAYOUT_MARGIN_LEFT = 2;   // 图表布局左边距
constexpr int CHART_LAYOUT_MARGIN_TOP = 10;   // 图表布局上边距
constexpr int CHART_LAYOUT_MARGIN_RIGHT = 2;  // 图表布局右边距
constexpr int CHART_LAYOUT_MARGIN_BOTTOM = 2; // 图表布局下边距
constexpr int CHART_LAYOUT_SPACING = 5;       // 图表布局间距

// 表格列宽配置
constexpr int TABLE_COL_WIDTH_NO = 60;       // 序号列宽度
constexpr int TABLE_COL_WIDTH_TIME = 110;    // 时间列宽度
constexpr int TABLE_COL_WIDTH_ADDRESS = 140; // 地址列宽度
constexpr int TABLE_COL_WIDTH_PROTO = 60;    // 协议列宽度
constexpr int TABLE_COL_WIDTH_LEN = 50;      // 长度列宽度
constexpr int TABLE_COL_WIDTH_INFO = 400;    // 信息列宽度

// 动画配置
constexpr int STOP_BUTTON_ANIM_DURATION = 1500; // 停止按钮动画持续时间（毫秒）
constexpr int STOP_BUTTON_ANIM_START = 20;      // 停止按钮动画起始值
constexpr int STOP_BUTTON_ANIM_END = 60;        // 停止按钮动画结束值

// 默认配置值
constexpr int DEFAULT_INTERVAL_US = 10000;       // 默认发送间隔（微秒）
constexpr int DEFAULT_SOCKET_INTERVAL_US = 1000; // Socket模式默认间隔（微秒）

// 统计更新配置
constexpr int STATS_UPDATE_MIN_INTERVAL_MS = 50; // 统计更新最小间隔（毫秒），防止除以接近0的数

// 单位转换
constexpr double MILLISECONDS_PER_SECOND = 1000.0; // 每秒毫秒数
constexpr int BYTES_PER_KILOBYTE = 1024;           // 每KB字节数
constexpr int PACKETS_PER_KILOPACKET = 1000;       // 每kpps包数

// 布局默认尺寸（像素）
constexpr int SPLITTER_BOTTOM_LOG_WIDTH = 150;   // 底部日志区域宽度
constexpr int SPLITTER_BOTTOM_TABLE_WIDTH = 550; // 底部表格区域宽度
constexpr int SPLITTER_BOTTOM_HEX_WIDTH = 300;   // 底部Hex区域宽度
constexpr int SPLITTER_MAIN_TOP_HEIGHT = 500;    // 主分割器顶部高度
constexpr int SPLITTER_MAIN_BOTTOM_HEIGHT = 200; // 主分割器底部高度
} // namespace UIConfig

namespace Ui {
class MainWindow;
}

// ============================================================================
// StatusDashboard 结构体
// ============================================================================
struct StatusDashboard {
    QLabel* lblCount;
    QLabel* lblBytes;
    QLabel* lblRate;

    void init(QStatusBar* bar, QWidget* parent) {
        bar->setStyleSheet("QStatusBar { background: #0f121a; color: #718096; border-top: 1px solid #1c2333; }"
                           "QStatusBar::item { border: none; }");

        lblCount = new QLabel("Sent: 0", parent);
        lblBytes = new QLabel("Data: 0 B", parent);
        lblRate = new QLabel("Speed: 0 pps | 0 B/s", parent);

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
        if (dBytes < 1024)
            byteStr = QString::number(dBytes) + " B";
        else if (dBytes < 1024 * 1024)
            byteStr = QString::number(dBytes / 1024.0, 'f', 1) + " KB";
        else if (dBytes < 1024 * 1024 * 1024)
            byteStr = QString::number(dBytes / (1024 * 1024.0), 'f', 2) + " MB";
        else
            byteStr = QString::number(dBytes / (1024 * 1024 * 1024.0), 'f', 2) + " GB";
        lblBytes->setText("Data: " + byteStr);

        QString ppsStr;
        if (pps >= 1000000)
            ppsStr = QString::number(pps / 1000000.0, 'f', 2) + " Mpps";
        else if (pps >= 1000)
            ppsStr = QString::number(pps / 1000.0, 'f', 1) + " kpps";
        else
            ppsStr = QString::number((int)pps) + " pps";

        QString bpsStr;
        if (bps >= 1024 * 1024 * 1024)
            bpsStr = QString::number(bps / (1024.0 * 1024 * 1024), 'f', 2) + " GB/s";
        else if (bps >= 1024 * 1024)
            bpsStr = QString::number(bps / (1024.0 * 1024), 'f', 2) + " MB/s";
        else if (bps >= 1024)
            bpsStr = QString::number(bps / 1024.0, 'f', 1) + " KB/s";
        else
            bpsStr = QString::number((int)bps) + " B/s";

        QString rateText = QString("Speed: %1 | %2").arg(ppsStr).arg(bpsStr);
        lblRate->setText(rateText);
        // 添加工具提示，说明这是本应用程序的发送速度
        lblRate->setToolTip("本应用程序发送数据包的速度（不包括接收的响应包和其他应用流量）");
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

    // [新增] 错误回调代理函数
    static void ErrorCallbackProxy(const char* error_msg) {
        if (m_instance) {
            emit m_instance->errorOccurred(QString::fromLocal8Bit(error_msg));
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
        // [新增] 注册错误回调
        config.error_callback = &PacketWorker::ErrorCallbackProxy;

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
    // [新增] 错误信号
    void errorOccurred(QString error_msg);

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
        config.log_callback = &SocketWorker::LogCallbackProxy; // [新增]

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
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
    bool eventFilter(QObject* watched, QEvent* event) override;

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
    void saveHistory(const QString& ip);
    void loadMacHistory();
    void saveMacHistory(const QString& mac);
    void loadConfig();
    void saveConfig();
    void setupResourceMonitor();
    void updateResourceDisplay(double cpuUsage, double memoryUsage);
    void updateNetworkDisplay(double uploadSpeed, double downloadSpeed);
    void updateStatsDisplay(uint64_t sent, uint64_t bytes); // 更新已发包数量和已发送字节显示
    void installEventFilterRecursive(QWidget* widget);      // 递归为所有子控件安装事件过滤器
    void setupTooltips();                                   // 为所有控件设置tooltip
    void appendLog(const QString& msg, int level = 0);

    void setupChart();

    void setupTrafficTable();
    void addPacketToTable(const QByteArray& data);

    HexRenderDelegate* m_hexDelegate;

    // [MVC] 数据包表格模型和视图
    PacketTableModel* m_packetModel; // 数据包表格模型
    QTableView* m_packetTableView;   // 数据包表格视图（替换 QTableWidget）

    void setupHexTableStyle();
    void updateHexTable(const QByteArray& data);
    void updateHexTableContent(const QByteArray& data); // 增量更新Hex表格内容（不重建表格）

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

    Ui::MainWindow* ui;
    QThread* workerThread;
    PacketWorker* worker;
    QPropertyAnimation* stopBtnAnim;
    QGraphicsDropShadowEffect* stopBtnEffect;
    QTimer* statsTimer;
    QElapsedTimer rateTimer;
    uint64_t lastTotalSent = 0;
    uint64_t lastTotalBytes = 0;
    StatusDashboard m_dashboard;
    QLabel* lblTargetPPS;
    QPushButton* btnGetMac;

    QList<double> m_ppsHistory;

    QList<double> m_rawByteHistory;
    // [修改] 拆分为两个图表的变量
    QChartView* viewPPS; // PPS 视图
    QChartView* viewBW;  // Bandwidth 视图

    QChart* chartPPS;
    QChart* chartBW;

    QSplineSeries* seriesPPS;
    QSplineSeries* seriesMbps;

    QValueAxis* axisX_PPS; // PPS 的时间轴
    QValueAxis* axisX_BW;  // BW 的时间轴

    QValueAxis* axisY_PPS; // PPS 的数值轴
    QValueAxis* axisY_BW;  // BW 的数值轴 (原 axisY_Mbps)

    qint64 m_chartTimeX;
    double m_maxPPS;
    double m_maxMbps;

    QThread* sockThread;
    SocketWorker* sockWorker;

    // [新增] 系统资源监控
    SystemResourceMonitor* m_resourceMonitor;
    CircularProgressWidget* m_cpuWidget;
    CircularProgressWidget* m_memoryWidget;
    CircularProgressWidget* m_uploadWidget;   // 上传速率
    CircularProgressWidget* m_downloadWidget; // 下载速率
    QLabel* m_packetsLabel;                   // 已发包数量（文本标签）
    QLabel* m_bytesLabel;                     // 已发送字节（文本标签）
    QWidget* m_resourceContainer;
};
