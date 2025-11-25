#pragma once

#include <QMainWindow>
#include <QThread>
#include <QTimer>
#include <QRegularExpression>

#include "sender_core.h"

// === 2. 使用命名空间 ===

// 包含 UI 生成的头文件
namespace Ui {
class MainWindow;
}

// === 后台发送线程 (保持不变) ===
class PacketWorker : public QObject {
    Q_OBJECT
public:
    QString interfaceName;
    QString srcMac, dstMac, srcIp, dstIp;
    int intervalUs;
    int pktType;
    // === 新增字段 ===
    int srcPort;
    int dstPort;
    int payloadLen;
    int tcpFlags; // <--- 新增字段
    QString dnsDomain;

public slots:
    void doSendWork() {
        g_is_sending = true;
        unsigned char s_mac[6], d_mac[6];
        unsigned char s_ip[4], d_ip[4];

        auto parseMac = [](QString s, unsigned char* buf){
            // === 修改点：加上 static const ===
            static const QRegularExpression regex("[:-]");

            QStringList p = s.split(regex);
            for(int i=0; i<6 && i<p.size(); ++i) buf[i] = p[i].toUInt(nullptr, 16);
        };
        auto parseIp = [](QString s, unsigned char* buf){
            QStringList p = s.split('.');
            for(int i=0; i<4 && i<p.size(); ++i) buf[i] = p[i].toUInt();
        };

        parseMac(srcMac, s_mac);
        parseMac(dstMac, d_mac);
        parseIp(srcIp, s_ip);
        parseIp(dstIp, d_ip);

        QByteArray devNameBytes = interfaceName.toUtf8();
        QByteArray domainBytes = dnsDomain.toUtf8(); // 转为 char*

        start_send_mode(
            devNameBytes.constData(),
            s_mac, d_mac, s_ip, d_ip,
            intervalUs,
            pktType,
            (unsigned short)srcPort,
            (unsigned short)dstPort,
            (unsigned short)payloadLen,
            (unsigned char)tcpFlags,
            domainBytes.constData() // <--- 传入域名
            );
        emit workFinished();
    }

signals:
    void workFinished();
};

// === 主窗口 ===
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


private slots:
    void onStartSendClicked();
    void onStopSendClicked();
    void onProtoToggled();

private:
    void loadInterfaces();


    Ui::MainWindow *ui;

    QThread *workerThread;
    PacketWorker *worker;


};
