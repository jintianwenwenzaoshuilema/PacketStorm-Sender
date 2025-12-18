#ifndef HEX_DELEGATE_H
#define HEX_DELEGATE_H

#include <QStyledItemDelegate>
#include <QPainter>
#include <QFontMetrics>
#include <QApplication>

class HexRenderDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    int hoverRow = -1;
    int hoverByteIndex = -1;

    // [新增] 定义统一的左内边距，确保高亮框和文字对齐
    static const int LEFT_PADDING = 4;

    explicit HexRenderDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override {
        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);

        const QWidget *widget = opt.widget;
        QStyle *style = widget ? widget->style() : QApplication::style();
        style->drawPrimitive(QStyle::PE_PanelItemViewItem, &opt, painter, widget);

        painter->save();
        painter->setFont(opt.font);

        QFontMetrics fm(opt.font);
        int charWidth = fm.horizontalAdvance(' ');
        int cellTop = opt.rect.top();
        int cellHeight = opt.rect.height();

        // [修改] 起始 X 坐标 = 单元格左边缘 + 统一的内边距
        int startX = opt.rect.left() + LEFT_PADDING;

        QString text = index.data(Qt::DisplayRole).toString();

        // --- 绘制高亮背景 ---
        if (index.row() == hoverRow && hoverByteIndex >= 0 && hoverByteIndex < 16) {
            QRect highlightRect;

            if (index.column() == 1) { // Hex 列
                int charStart = hoverByteIndex * 3;
                if (hoverByteIndex >= 8) charStart += 1;

                // [修改] 使用 startX 计算位置
                int x = startX + (charStart * charWidth);
                highlightRect = QRect(x, cellTop, charWidth * 2, cellHeight);
            }
            else if (index.column() == 2) { // ASCII 列
                // [修改] 使用 startX 计算位置
                int x = startX + (hoverByteIndex * charWidth);
                highlightRect = QRect(x, cellTop, charWidth, cellHeight);
            }

            if (!highlightRect.isEmpty()) {
                painter->fillRect(highlightRect, QColor(0, 230, 118, 60));
                painter->setPen(QColor(0, 230, 118));
                painter->drawRect(highlightRect.adjusted(0, 0, -1, -1));
            }
        }

        // --- 绘制文字 ---
        if (index.column() == 0) {
            painter->setPen(QColor("#718096"));
            // Offset 列保持右对齐，不受 LEFT_PADDING 影响，但减去一些右边距
            painter->drawText(opt.rect.adjusted(0,0,-10,0), Qt::AlignRight | Qt::AlignVCenter, text);
        }
        else {
            if (index.column() == 1) painter->setPen(QColor("#00e676"));
            else if (index.column() == 2) painter->setPen(QColor("#a0a8b7"));

            // [修改] 文字绘制区域也应用相同的 LEFT_PADDING
            QRect textRect = opt.rect;
            textRect.setLeft(startX);
            painter->drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter, text);
        }

        painter->restore();
    }
};

#endif // HEX_DELEGATE_H
