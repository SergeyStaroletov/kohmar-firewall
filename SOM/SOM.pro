#-------------------------------------------------
#
# Project created by QtCreator 2013-05-02T15:45:14
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = SOM
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
    neuron.cpp \
    samplesom.cpp \
    selforganizedmap.cpp

HEADERS  += mainwindow.h \
    neuron.h \
    samplesom.h \
    selforganizedmap.h

QMAKE_CXXFLAGS = -g
QMAKE_CFLAGS = -g
QMAKE_LFLAGS = -g

FORMS    += mainwindow.ui

OTHER_FILES += \
    toRecognize.dat \
    flow.samples
