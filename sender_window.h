#pragma once

#include <QMainWindow>
#include <QThread>
#include <QTimer>
#include <QRegularExpression>
#include "sender_core.h" // 包含新的结构体定义

namespace Ui {
class MainWindow;
}

// === 修改后的 PacketWorker 类 ===
class PacketWorker : public QObject {
    Q_OBJECT
public:
    // 直接持有配置对象，避免一大堆成员变量
    SenderConfig config;

    // 专门用于存储自定义载荷数据的缓冲区
    // 因为 SenderConfig 里只是 const char* 指针，必须保证数据本身在发送期间有效
    QByteArray customDataBuffer;

public slots:
    void doSendWork() {
        // 更新指针指向当前的 buffer 数据
        if (config.payload_mode == PAYLOAD_CUSTOM) {
            config.custom_data = customDataBuffer.constData();
            config.custom_data_len = customDataBuffer.length();
        } else {
            config.custom_data = nullptr;
            config.custom_data_len = 0;
        }

        g_is_sending = true;
        // 调用优化后的接口
        start_send_mode(&config);
        emit workFinished();
    }

signals:
    void workFinished();
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartSendClicked();
    void onStopSendClicked();
    void onProtoToggled();
    void onPayloadModeChanged(); // <--- 新增槽函数

private:
    void loadInterfaces();

    Ui::MainWindow *ui;
    QThread *workerThread;
    PacketWorker *worker;
};
