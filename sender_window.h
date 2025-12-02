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

namespace Ui {
class MainWindow;
}

// ============================================================================
// [修改] 状态看板结构体：去除竖线，恢复默认靠右
// ============================================================================
struct StatusDashboard {
    QLabel *lblCount;
    QLabel *lblBytes;
    QLabel *lblRate;

    // --- 初始化函数 ---
    void init(QStatusBar* bar, QWidget* parent) {
        // 1. 设置状态栏整体样式
        // [关键修改] 添加 QStatusBar::item { border: none; } 以去除系统自带的分割线
        bar->setStyleSheet(
            "QStatusBar { background: #0f121a; color: #718096; border-top: 1px solid #1c2333; }"
            "QStatusBar::item { border: none; }"
            );

        // 2. 创建标签
        lblCount = new QLabel("Sent: 0", parent);
        lblBytes = new QLabel("Data: 0 B", parent);
        lblRate  = new QLabel("Speed: 0 pps | 0 B/s", parent);

        // 3. 固定宽度 (保持之前的设定，防止跳动)
        lblCount->setFixedWidth(150);
        lblBytes->setFixedWidth(150);
        lblRate->setFixedWidth(270);

        // 4. 设置对齐方式
        lblCount->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        lblBytes->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        lblRate->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        // 5. 设置颜色样式
        // [关键修改] 去掉了 lblRate 的 border-left (竖线)
        lblCount->setStyleSheet("color: #00e676; font-weight: bold; padding-right: 5px;");
        lblBytes->setStyleSheet("color: #00f0ff; font-weight: bold; padding-right: 5px;");
        lblRate->setStyleSheet("color: #FFB74D; font-weight: bold; padding-left: 10px;"); // <--- 删除了 border-left

        // 6. 添加到状态栏 (使用 addPermanentWidget 让它们靠右排列)
        bar->addPermanentWidget(lblCount);
        bar->addPermanentWidget(lblBytes);
        bar->addPermanentWidget(lblRate);
    }

    // --- 更新函数 (保持不变) ---
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

    // 静态回调函数
    static void StatsCallbackProxy(uint64_t sent, uint64_t bytes) {
        // [修复原理] 这里需要 m_instance 有值才能发出信号
        if (m_instance) {
            emit m_instance->statsUpdated(sent, bytes);
        }
    }

public slots:
    void doSendWork() {
        // ============================================================
        // 【关键修复】必须在这里赋值，否则静态回调函数找不到实例！
        // ============================================================
        m_instance = this;

        if (config.payload_mode == PAYLOAD_CUSTOM) {
            config.custom_data = customDataBuffer.constData();
            config.custom_data_len = customDataBuffer.length();
        } else {
            config.custom_data = nullptr;
            config.custom_data_len = 0;
        }
        config.stats_callback = &PacketWorker::StatsCallbackProxy;

        g_is_sending = true;
        start_send_mode(&config);

        m_instance = nullptr; // 结束后清理
        emit workFinished();
    }
signals:
    void workFinished();
    void statsUpdated(uint64_t sent, uint64_t bytes);

private:
    static PacketWorker* m_instance;
};

// ============================================================================
// MainWindow 类 (保持不变)
// ============================================================================
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartSendClicked();
    void onStopSendClicked();
    void onProtoToggled();
    void onPayloadModeChanged();
    void updateStats(uint64_t currSent, uint64_t currBytes);

private:
    void loadInterfaces();

    Ui::MainWindow *ui;
    QThread *workerThread;
    PacketWorker *worker;
    QPropertyAnimation *stopBtnAnim;
    QGraphicsDropShadowEffect *stopBtnEffect;

    // === 统计相关 ===
    QTimer *statsTimer;
    QElapsedTimer rateTimer;
    uint64_t lastTotalSent = 0;
    uint64_t lastTotalBytes = 0;

    // 使用结构体统一管理底部状态栏
    StatusDashboard m_dashboard;

    // 中间的 PPS 目标显示
    QLabel *lblTargetPPS;
};
