#pragma once

#include <QElapsedTimer>
#include <QPainter>
#include <QString>
#include <QTimer>
#include <QWidget>

#ifdef _WIN32
// 确保使用宽字符版本的 PDH API
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <iphlpapi.h>
#include <pdh.h>
#include <windows.h>

#pragma comment(lib, "pdh.lib")
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

// ============================================================================
// [新增] 系统资源监控类
// ============================================================================
class SystemResourceMonitor : public QObject {
    Q_OBJECT

  public:
    SystemResourceMonitor(QObject* parent = nullptr);
    ~SystemResourceMonitor();

    double getCpuUsage();    // 获取 CPU 使用率 (0-100)
    double getMemoryUsage(); // 获取内存使用率 (0-100)
    qint64 getTotalMemory(); // 获取总内存 (字节)
    qint64 getUsedMemory();  // 获取已用内存 (字节)

  signals:
    void resourceUpdated(double cpuUsage, double memoryUsage);
    void networkStatsUpdated(double uploadSpeed, double downloadSpeed); // 上传和下载速率 (MB/s)
    void logMessage(const QString& message, int level = 0);             // 日志消息信号

  public slots:
    void startMonitoring(int intervalMs = 1000);
    void stopMonitoring();
    void setMonitorInterface(const QString& interfaceName); // 设置要监控的网卡名称
    void resetNetworkStats();                               // 重置网络统计计数器

  private slots:
    void updateResources();
    void updateNetworkStats();

  private:
    QTimer* m_timer;
    QTimer* m_networkUpdateTimer; // 网卡流量更新定时器

#ifdef _WIN32
    // Windows 性能计数器
    PDH_HQUERY m_cpuQuery;
    PDH_HCOUNTER m_cpuCounter;
    bool m_cpuCounterInitialized;

    // 内存信息
    MEMORYSTATUSEX m_memInfo;

    // 网卡流量监控
    QString m_monitorInterfaceName; // 要监控的网卡名称（pcap名称）
    QString m_monitorInterfaceIp;   // 要监控的网卡 IP 地址（用于备选查找方案）
    int m_cachedAdapterIndex;       // 缓存的适配器索引，避免重复查找
    ULONG64 m_lastBytesSent;        // 上次发送字节数
    ULONG64 m_lastBytesRecv;        // 上次接收字节数
    qint64 m_lastNetworkUpdateTime; // 上次更新时间戳（毫秒，使用系统时间戳）
    bool m_networkCounterInitialized;
#endif

    double m_lastCpuUsage;
    double m_lastMemoryUsage;

    // 辅助函数：通过 IP 地址在 GetIfTable 中查找适配器索引
    int findAdapterIndexByIp(const QString& ipAddress);
};

// ============================================================================
// [新增] 现代化圆形进度条组件
// ============================================================================
class CircularProgressWidget : public QWidget {
    Q_OBJECT
    Q_PROPERTY(double value READ value WRITE setValue)
    Q_PROPERTY(QString label READ label WRITE setLabel)
    Q_PROPERTY(QString unit READ unit WRITE setUnit)
    Q_PROPERTY(QColor color READ color WRITE setColor)

  public:
    explicit CircularProgressWidget(QWidget* parent = nullptr);

    double value() const { return m_value; }
    void setValue(double value);

    QString label() const { return m_label; }
    void setLabel(const QString& label);

    QString unit() const { return m_unit; }
    void setUnit(const QString& unit);

    QColor color() const { return m_color; }
    void setColor(const QColor& color);

  protected:
    void paintEvent(QPaintEvent* event) override;

  private:
    double m_value;  // 0-100
    QString m_label; // 标签文本（如 "CPU"）
    QString m_unit;  // 单位文本（如 "%"）
    QColor m_color;  // 进度条颜色

    void drawCircularProgress(QPainter& painter, const QRect& rect, double value, const QColor& color);
};
