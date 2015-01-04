#-------------------------------------------------
#
# Project created by QtCreator 2014-12-25T14:03:55
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SWD
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui

INCLUDEPATH+= /usr/local/qwt-6.1.2/include
LIBS += -L/usr/local/lib -lpcap
LIBS+= -L/usr/local/qwt-6.1.2/lib -lqwt -Wl,-rpath,/usr/local/qwt-6.1.2/lib

