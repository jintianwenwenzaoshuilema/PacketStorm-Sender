#include "sender_window.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QApplication::setStyle("Fusion"); // 融合风格，作为 Dark Theme 的基础

    MainWindow w;
    w.show();
    return a.exec();
}
