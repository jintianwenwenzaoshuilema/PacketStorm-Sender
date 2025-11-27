QT += core gui



greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    main.cpp \
    sender_core.cpp \
    sender_window.cpp

HEADERS += \
    sender_core.h \
    sender_window.h

FORMS += \
    sender.ui

TRANSLATIONS +=
CONFIG += lrelease
CONFIG += embed_translations
CONFIG += c++20


INCLUDEPATH += "C:\WpdPack\Include"
LIBS += "-LC:\WpdPack\Lib\x64" -lwpcap -lws2_32

DEFINES += WIN32
DEFINES += WPCAP
DEFINES += HAVE_REMOTE

RC_ICONS = icon.ico


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target


