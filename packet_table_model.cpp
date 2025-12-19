#include "packet_table_model.h"

// ============================================================================
// [MVC] PacketTableModel 实现
// ============================================================================
PacketTableModel::PacketTableModel(QObject* parent) : QAbstractTableModel(parent) {}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    Q_UNUSED(parent);
    return m_packets.size();
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    Q_UNUSED(parent);
    return ColCount;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= m_packets.size() || index.column() >= ColCount) {
        return QVariant();
    }

    const PacketInfo& info = m_packets[index.row()];

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case ColNo:
                return info.packetNumber;
            case ColTime:
                return info.timestamp.toString("HH:mm:ss.zzz");
            case ColSource:
                return info.src;
            case ColDestination:
                return info.dst;
            case ColProtocol:
                return info.proto;
            case ColLength:
                return info.length;
            case ColInfo:
                return info.info;
            default:
                return QVariant();
        }
    } else if (role == Qt::UserRole) {
        // 返回原始数据（用于 Hex 视图）
        return info.rawData;
    } else if (role == Qt::TextAlignmentRole) {
        // 某些列居中对齐
        if (index.column() == ColNo || index.column() == ColProtocol || index.column() == ColLength) {
            return Qt::AlignCenter;
        }
    }

    return QVariant();
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        static const QStringList headers = {"No.", "Time", "Source", "Destination", "Proto", "Len", "Info"};
        if (section < headers.size()) {
            return headers[section];
        }
    }
    return QVariant();
}

void PacketTableModel::addPacket(const PacketInfo& info) {
    // 限制行数，防止内存溢出
    if (m_packets.size() >= MAX_ROWS) {
        // 移除第一行
        beginRemoveRows(QModelIndex(), 0, 0);
        m_packets.removeFirst();
        endRemoveRows();
    }

    // 添加新行
    int newRow = m_packets.size();
    beginInsertRows(QModelIndex(), newRow, newRow);
    m_packets.append(info);
    endInsertRows();
}

PacketTableModel::PacketInfo PacketTableModel::getPacket(int row) const {
    if (row >= 0 && row < m_packets.size()) {
        return m_packets[row];
    }
    return PacketInfo();
}

QByteArray PacketTableModel::getRawData(int row) const {
    if (row >= 0 && row < m_packets.size()) {
        return m_packets[row].rawData;
    }
    return QByteArray();
}

void PacketTableModel::clear() {
    if (m_packets.isEmpty()) {
        return;
    }
    beginResetModel();
    m_packets.clear();
    endResetModel();
}
