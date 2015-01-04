#-------------------------------------------------
#
# Project created by QtCreator 2014-12-18T13:03:47
#
#-------------------------------------------------
INCLUDEPATH += /usr/local/qwt-6.1.2/include

LIBS += -L/usr/local/qwt-6.1.2/lib -lqwt -Wl,-rpath,/usr/local/qwt-6.1.2/lib

QT       += core gui

QT += widgets

TARGET = testui
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui
