TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        main.cpp

HEADERS += \
    get_mac.h \
    stc.h
