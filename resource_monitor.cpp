#include "resource_monitor.h"
#include <QDateTime>
#include <QDebug>
#include <QElapsedTimer>
#include <vector>

#ifdef _WIN32
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <ws2tcpip.h>
// 确保使用宽字符版本的 PDH API
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#endif

// ============================================================================
// SystemResourceMonitor 实现
// ============================================================================
SystemResourceMonitor::SystemResourceMonitor(QObject* parent)
    : QObject(parent), m_timer(nullptr), m_lastCpuUsage(0.0), m_lastMemoryUsage(0.0) {
#ifdef _WIN32
    m_cpuCounterInitialized = false;
    m_cpuQuery = nullptr;
    m_cpuCounter = nullptr;
    m_cachedAdapterIndex = -1;

    // 初始化 CPU 性能计数器
    // 注意：PDH API 需要 UNICODE 定义才能使用宽字符版本
    PDH_STATUS status = PdhOpenQuery(nullptr, 0, &m_cpuQuery);
    if (status == ERROR_SUCCESS) {
        // 使用宽字符版本的计数器路径
        const wchar_t* counterPath = L"\\Processor(_Total)\\% Processor Time";
        status = PdhAddCounterW(m_cpuQuery, counterPath, 0, &m_cpuCounter);
        if (status == ERROR_SUCCESS) {
            m_cpuCounterInitialized = true;
            // 第一次查询，初始化计数器
            PdhCollectQueryData(m_cpuQuery);
        }
    }

    // 初始化内存信息结构
    m_memInfo.dwLength = sizeof(MEMORYSTATUSEX);
#endif
}

SystemResourceMonitor::~SystemResourceMonitor() {
    stopMonitoring();
#ifdef _WIN32
    if (m_cpuQuery) {
        if (m_cpuCounter) {
            PdhRemoveCounter(m_cpuCounter);
        }
        PdhCloseQuery(m_cpuQuery);
    }
#endif
}

double SystemResourceMonitor::getCpuUsage() {
#ifdef _WIN32
    if (!m_cpuCounterInitialized) return 0.0;

    PDH_FMT_COUNTERVALUE counterValue;
    if (PdhCollectQueryData(m_cpuQuery) == ERROR_SUCCESS) {
        if (PdhGetFormattedCounterValue(m_cpuCounter, PDH_FMT_DOUBLE, nullptr, &counterValue) == ERROR_SUCCESS) {
            m_lastCpuUsage = counterValue.doubleValue;
            return m_lastCpuUsage;
        }
    }
    return m_lastCpuUsage;
#else
    return 0.0;
#endif
}

double SystemResourceMonitor::getMemoryUsage() {
#ifdef _WIN32
    if (GlobalMemoryStatusEx(&m_memInfo)) {
        DWORDLONG totalMem = m_memInfo.ullTotalPhys;
        DWORDLONG usedMem = totalMem - m_memInfo.ullAvailPhys;
        m_lastMemoryUsage = (double)usedMem / (double)totalMem * 100.0;
        return m_lastMemoryUsage;
    }
    return m_lastMemoryUsage;
#else
    return 0.0;
#endif
}

qint64 SystemResourceMonitor::getTotalMemory() {
#ifdef _WIN32
    if (GlobalMemoryStatusEx(&m_memInfo)) {
        return (qint64)m_memInfo.ullTotalPhys;
    }
#endif
    return 0;
}

qint64 SystemResourceMonitor::getUsedMemory() {
#ifdef _WIN32
    if (GlobalMemoryStatusEx(&m_memInfo)) {
        return (qint64)(m_memInfo.ullTotalPhys - m_memInfo.ullAvailPhys);
    }
#endif
    return 0;
}

void SystemResourceMonitor::startMonitoring(int intervalMs) {
    if (m_timer) {
        m_timer->stop();
        delete m_timer;
    }

    m_timer = new QTimer(this);
    connect(m_timer, &QTimer::timeout, this, &SystemResourceMonitor::updateResources);
    m_timer->start(intervalMs);

    // 立即更新一次
    updateResources();

    // 启动网卡流量监控（每秒更新一次）
    if (!m_networkUpdateTimer) {
        m_networkUpdateTimer = new QTimer(this);
        connect(m_networkUpdateTimer, &QTimer::timeout, this, &SystemResourceMonitor::updateNetworkStats);
    }
    m_networkUpdateTimer->start(1000); // 每1秒更新一次网卡流量
    updateNetworkStats();              // 立即更新一次（用于初始化）
}

void SystemResourceMonitor::stopMonitoring() {
    if (m_timer) {
        m_timer->stop();
        m_timer->deleteLater();
        m_timer = nullptr;
    }
    if (m_networkUpdateTimer) {
        m_networkUpdateTimer->stop();
        m_networkUpdateTimer->deleteLater();
        m_networkUpdateTimer = nullptr;
    }
    // 注意：停止监控时不重置网络统计，保持统计的连续性
}

void SystemResourceMonitor::resetNetworkStats() {
#ifdef _WIN32
    // 重置网络统计计数器，下次更新时会重新初始化
    m_networkCounterInitialized = false;
    m_lastBytesSent = 0;
    m_lastBytesRecv = 0;
    m_lastNetworkUpdateTime = 0;
    // 立即发送0速度，清除显示
    emit networkStatsUpdated(0.0, 0.0);
#endif
}

void SystemResourceMonitor::updateResources() {
    double cpu = getCpuUsage();
    double memory = getMemoryUsage();
    emit resourceUpdated(cpu, memory);
}

void SystemResourceMonitor::setMonitorInterface(const QString& interfaceName) {
#ifdef _WIN32
    // 如果接口名称没有变化，不需要重新查找
    if (m_monitorInterfaceName == interfaceName && m_cachedAdapterIndex != -1) {
        return;
    }

    m_monitorInterfaceName = interfaceName;
    m_networkCounterInitialized = false;
    m_lastBytesSent = 0;
    m_lastBytesRecv = 0;
    m_lastNetworkUpdateTime = 0;

    // 先获取 IP 地址
    int bracePos = interfaceName.indexOf('{');
    if (bracePos != -1) {
        QString targetGuid = interfaceName.mid(bracePos);
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

        if (dwRetVal == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                QString currentName = QString(pAdapter->AdapterName);
                if (targetGuid.compare(currentName, Qt::CaseInsensitive) == 0) {
                    m_monitorInterfaceIp = QString(pAdapter->IpAddressList.IpAddress.String);
                    if (m_monitorInterfaceIp == "0.0.0.0") m_monitorInterfaceIp.clear();
                    break;
                }
                pAdapter = pAdapter->Next;
            }
        }
        // buffer 自动释放，无需手动 free
    }

    // 通过 IP 地址查找适配器索引（更可靠的方法）
    if (!m_monitorInterfaceIp.isEmpty() && m_monitorInterfaceIp != "0.0.0.0") {
        m_cachedAdapterIndex = findAdapterIndexByIp(m_monitorInterfaceIp);
    } else {
        m_cachedAdapterIndex = -1;
    }

    // 如果监控已启动，立即更新一次
    if (m_networkUpdateTimer && m_networkUpdateTimer->isActive()) {
        updateNetworkStats();
    }
#endif
}

void SystemResourceMonitor::updateNetworkStats() {
#ifdef _WIN32
    if (m_monitorInterfaceName.isEmpty() || m_cachedAdapterIndex == -1) {
        emit networkStatsUpdated(0.0, 0.0);
        return;
    }

    // 直接使用缓存的适配器索引，不再重复查找
    int adapterIndex = m_cachedAdapterIndex;

    // 使用 GetIfTable 获取适配器统计信息（更通用的 API）
    // [优化] 使用 RAII 管理内存，自动释放
    ULONG dwSize = 0;

    // 获取所需缓冲区大小
    if (GetIfTable(nullptr, &dwSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        emit networkStatsUpdated(0.0, 0.0);
        return;
    }

    std::vector<BYTE> buffer(dwSize);
    PMIB_IFTABLE pIfTable = reinterpret_cast<PMIB_IFTABLE>(buffer.data());

    // 获取适配器表
    DWORD result = GetIfTable(pIfTable, &dwSize, FALSE);
    if (result != NO_ERROR) {
        emit networkStatsUpdated(0.0, 0.0);
        return;
    }

    // 查找对应的适配器
    bool found = false;
    for (DWORD i = 0; i < pIfTable->dwNumEntries; i++) {
        if (pIfTable->table[i].dwIndex == (DWORD)adapterIndex) {
            ULONG64 currentBytesSent = pIfTable->table[i].dwOutOctets;
            ULONG64 currentBytesRecv = pIfTable->table[i].dwInOctets;

            // 使用系统时间戳来确保精确的1秒间隔计算
            qint64 currentTimeMs = QDateTime::currentMSecsSinceEpoch();

            if (m_networkCounterInitialized && m_lastNetworkUpdateTime > 0) {
                qint64 timeDelta = currentTimeMs - m_lastNetworkUpdateTime;

                // 确保时间差至少为500ms，避免因定时器不精确导致的计算错误
                // 如果时间差太小，等待下一次更新
                if (timeDelta < 500) {
                    // 时间差太小，跳过本次更新，等待下一次
                    return;
                }

                // 计算速率 (字节/毫秒 -> MB/秒)
                ULONG64 bytesSentDelta =
                    (currentBytesSent >= m_lastBytesSent) ? (currentBytesSent - m_lastBytesSent) : 0;
                ULONG64 bytesRecvDelta =
                    (currentBytesRecv >= m_lastBytesRecv) ? (currentBytesRecv - m_lastBytesRecv) : 0;

                // 使用实际时间差计算速度，确保每秒更新
                double uploadSpeed = (double)bytesSentDelta / (1024.0 * 1024.0) * 1000.0 / timeDelta;
                double downloadSpeed = (double)bytesRecvDelta / (1024.0 * 1024.0) * 1000.0 / timeDelta;

                // 限制最大值，避免异常值
                uploadSpeed = qBound(0.0, uploadSpeed, 10000.0);
                downloadSpeed = qBound(0.0, downloadSpeed, 10000.0);

                // 更新基准值，为下一次计算做准备（在计算速度之后更新）
                m_lastBytesSent = currentBytesSent;
                m_lastBytesRecv = currentBytesRecv;
                m_lastNetworkUpdateTime = currentTimeMs;

                emit networkStatsUpdated(uploadSpeed, downloadSpeed);
            } else {
                // 第一次初始化，只记录当前值，不计算速率
                m_lastBytesSent = currentBytesSent;
                m_lastBytesRecv = currentBytesRecv;
                m_lastNetworkUpdateTime = currentTimeMs;
                m_networkCounterInitialized = true;
                emit networkStatsUpdated(0.0, 0.0);
            }

            found = true;
            break;
        }
    }
    // buffer 自动释放，无需手动 free
    if (!found) {
        emit networkStatsUpdated(0.0, 0.0);
    }
#else
    emit networkStatsUpdated(0.0, 0.0);
#endif
}

int SystemResourceMonitor::findAdapterIndexByIp(const QString& ipAddress) {
#ifdef _WIN32
    if (ipAddress.isEmpty() || ipAddress == "0.0.0.0") {
        return -1;
    }

    // 通过 IP 地址在 GetIpAddrTable 中查找适配器索引
    // [优化] 使用 RAII 管理内存，自动释放
    ULONG ipTableSize = 0;

    // 获取 IP 地址表所需缓冲区大小
    if (GetIpAddrTable(nullptr, &ipTableSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return -1;
    }

    std::vector<BYTE> buffer(ipTableSize);
    MIB_IPADDRTABLE* pIpAddrTable = reinterpret_cast<MIB_IPADDRTABLE*>(buffer.data());

    // 获取 IP 地址表
    DWORD result = GetIpAddrTable(pIpAddrTable, &ipTableSize, FALSE);
    int adapterIndex = -1;

    if (result == NO_ERROR) {
        // 将 IP 地址字符串转换为网络字节序
        struct in_addr targetAddr;
        // 使用 inet_addr 将 IP 字符串转换为网络字节序
        targetAddr.S_un.S_addr = inet_addr(ipAddress.toLocal8Bit().constData());

        if (targetAddr.S_un.S_addr != INADDR_NONE) {
            DWORD targetIp = targetAddr.S_un.S_addr;

            // 在 IP 地址表中查找匹配的 IP
            for (DWORD i = 0; i < pIpAddrTable->dwNumEntries; i++) {
                if (pIpAddrTable->table[i].dwAddr == targetIp) {
                    adapterIndex = (int)pIpAddrTable->table[i].dwIndex;
                    break;
                }
            }
        }
    }

    // buffer 自动释放，无需手动 free
    return adapterIndex;
#else
    return -1;
#endif
}

// ============================================================================
// CircularProgressWidget 实现
// ============================================================================
CircularProgressWidget::CircularProgressWidget(QWidget* parent)
    : QWidget(parent), m_value(0.0), m_label(""), m_unit("%"), m_color(QColor("#00e676")) {
    setMinimumSize(80, 80);
    setMaximumSize(120, 120);
}

void CircularProgressWidget::setValue(double value) {
    // 对于速率显示，不限制最大值（MB/s 可能超过 100）
    if (m_unit == "%") {
        m_value = qBound(0.0, value, 100.0);
    } else {
        m_value = qMax(0.0, value); // 只限制最小值
    }
    update(); // 触发重绘
}

void CircularProgressWidget::setLabel(const QString& label) {
    m_label = label;
    update();
}

void CircularProgressWidget::setUnit(const QString& unit) {
    m_unit = unit;
    update();
}

void CircularProgressWidget::setColor(const QColor& color) {
    m_color = color;
    update();
}

void CircularProgressWidget::paintEvent(QPaintEvent* event) {
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    QRect rect = this->rect();
    // 留出边距避免切边
    int margin = 5;
    int size = qMin(rect.width(), rect.height()) - margin * 2;
    QRect circleRect((rect.width() - size) / 2, (rect.height() - size) / 2, size, size);

    // 计算圆环粗细，随尺寸调整
    int strokeWidth = qMax(6, size / 10);

    // 绘制背景圆环（深色背景）
    QPen bgPen(QColor("#1c2333"));
    bgPen.setWidth(strokeWidth);
    bgPen.setCapStyle(Qt::RoundCap);
    painter.setPen(bgPen);
    QRect arcRect = circleRect.adjusted(strokeWidth/2, strokeWidth/2, -strokeWidth/2, -strokeWidth/2);
    painter.drawArc(arcRect, 0, 5760); 

    // 绘制进度圆环
    double maxValue = 100.0;
    if (m_unit != "%") {
        if (m_unit == "KB/s") maxValue = 1024.0;
        else if (m_unit == "MB/s") maxValue = 100.0;
        else if (m_unit == "GB/s") maxValue = 1.0;
        else if (m_unit == "K") maxValue = 1000.0;
        else if (m_unit == "M") maxValue = 100.0;
        else if (m_unit == "B") maxValue = 10.0;
        else if (m_unit == "KB") maxValue = 1024.0;
        else if (m_unit == "MB") maxValue = 1024.0;
        else if (m_unit == "GB") maxValue = 10.0;
        else if (m_unit.isEmpty()) maxValue = 1000.0;
    }
    double progressPercent = (m_unit == "%") ? m_value : qMin(100.0, (m_value / maxValue) * 100.0);
    
    if (progressPercent > 0) {
        // 计算角度
        constexpr int START_ANGLE = 90 * 16;
        int spanAngle = -(int)(progressPercent / 100.0 * 360 * 16);

        // 渐变效果
        QConicalGradient gradient(circleRect.center(), 90);
        gradient.setColorAt(0.0, m_color);
        gradient.setColorAt(1.0, m_color.darker(150));

        QPen progressPen(QBrush(gradient), strokeWidth);
        progressPen.setCapStyle(Qt::RoundCap);
        painter.setPen(progressPen);
        painter.drawArc(arcRect, START_ANGLE, spanAngle);
    }

    // --- 绘制文本 ---
    // 标签文本（顶部，较小）
    QFont labelFont("JetBrains Mono", qMax(7, size / 12), QFont::Medium);
    painter.setFont(labelFont);
    painter.setPen(QColor("#718096"));
    QRect labelRect = circleRect;
    labelRect.setTop(circleRect.center().y() - size/4 - 5);
    labelRect.setHeight(size/4);
    painter.drawText(labelRect, Qt::AlignCenter, m_label);

    // 数值文本（中心，较大）
    QFont valueFont("JetBrains Mono", qMax(9, size / 5), QFont::Bold);
    painter.setFont(valueFont);
    painter.setPen(m_color);
    
    QString valueText;
    if (m_unit == "%") valueText = QString::number(m_value, 'f', 1);
    else if (m_unit == "MB/s") valueText = QString::number(m_value, 'f', 1); 
    else if (m_unit == "KB/s") valueText = QString::number((int)m_value);
    else if (m_unit.isEmpty()) valueText = QString::number((int)m_value);
    else valueText = QString::number(m_value, 'f', 1);

    // 自动缩放字体大小以适应宽度
    int textWidth = painter.fontMetrics().horizontalAdvance(valueText);
    if (textWidth > size * 0.8) {
        QFont smallerFont = valueFont;
        smallerFont.setPointSizeF(valueFont.pointSizeF() * (size * 0.8 / textWidth));
        painter.setFont(smallerFont);
    }

    QRect valueRect = circleRect;
    valueRect.setTop(circleRect.center().y() - size/8);
    valueRect.setHeight(size/3);
    painter.drawText(valueRect, Qt::AlignCenter, valueText);

    // 单位文本（底部，较小）
    QFont unitFont("JetBrains Mono", qMax(6, size / 15));
    painter.setFont(unitFont);
    painter.setPen(QColor("#4a5568"));
    QRect unitRect = circleRect;
    unitRect.setTop(circleRect.center().y() + size/5);
    unitRect.setHeight(size/5);
    painter.drawText(unitRect, Qt::AlignCenter, m_unit);
}

void CircularProgressWidget::drawCircularProgress(QPainter& painter, const QRect& rect, double value,
                                                  const QColor& color) {
    // 该函数已被合并到 paintEvent 中以优化性能和一致性
    Q_UNUSED(painter); Q_UNUSED(rect); Q_UNUSED(value); Q_UNUSED(color);
}
