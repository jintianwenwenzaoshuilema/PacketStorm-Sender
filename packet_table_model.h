#pragma once

#include <QAbstractTableModel>
#include <QDateTime>
#include <QList>

// ============================================================================
// [MVC] PacketTableModel - 数据包表格模型
// ============================================================================
class PacketTableModel : public QAbstractTableModel {
    Q_OBJECT

  public:
    enum Columns {
        ColNo = 0,      // 序号
        ColTime,        // 时间
        ColSource,      // 源地址
        ColDestination, // 目标地址
        ColProtocol,    // 协议
        ColLength,      // 长度
        ColInfo,        // 信息
        ColCount        // 列数
    };

    // 数据包信息结构（与 MainWindow::PacketInfo 对应）
    struct PacketInfo {
        int packetNumber;    // 包序号
        QDateTime timestamp; // 时间戳
        QString src;         // 源地址
        QString dst;         // 目标地址
        QString proto;       // 协议
        int length;          // 长度
        QString info;        // 信息
        QByteArray rawData;  // 原始数据
    };

    explicit PacketTableModel(QObject* parent = nullptr);

    // QAbstractTableModel 接口实现
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    // 业务逻辑方法
    void addPacket(const PacketInfo& info);
    PacketInfo getPacket(int row) const;
    QByteArray getRawData(int row) const;
    void clear();

  private:
    QList<PacketInfo> m_packets;          // 数据存储
    static constexpr int MAX_ROWS = 1000; // 最大行数
};
