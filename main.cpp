#include "sender_window.h"
#include <QApplication>
#include <QFontDatabase> // 引入字体数据库头文件
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // === 1. 加载自定义字体 ===
    // 返回字体ID，如果为 -1 表示加载失败
    int fontId = QFontDatabase::addApplicationFont(":/fonts/JetBrainsMono-Regular.ttf");

    QString fontFamilyName;
    if (fontId != -1) {
        // 获取字体的真实家族名称 (通常是 "JetBrains Mono")
        fontFamilyName = QFontDatabase::applicationFontFamilies(fontId).at(0);
        qDebug() << "Custom font loaded:" << fontFamilyName;
    } else {
        qDebug() << "Failed to load custom font!";
        // 如果加载失败，回退到系统等宽字体
        fontFamilyName = "Consolas";
    }

    // === 2. 设置全局默认字体 (可选) ===
    // 如果你想让整个软件都用这个字体
    QFont font(fontFamilyName);
    font.setPointSize(10); // 设置字号
    a.setFont(font);

    // === 3. 如果只想在特定地方使用，不要设置 a.setFont，而是通过样式表 ===
    // 在这里我们把字体名字传给样式表，防止字体名有空格导致识别错误
    // 稍后在 styleSheet 里用 font-family: "JetBrains Mono"; 即可

    MainWindow w;
    w.show();
    return a.exec();
}
