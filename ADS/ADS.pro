#-------------------------------------------------
#
# Project created by QtCreator 2013-04-08T20:07:59
#
#-------------------------------------------------

QT       += core gui sql network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ADS
TEMPLATE = app

#INCLUDEPATH += /usr/src/linux-headers-3.5.0-17-generic/include/

SOURCES += main.cpp\
    ../Common/utils/StdThread.cpp \
        mainwindow.cpp \
    rulesform.cpp \
    addruleform.cpp \
    ../Common/adressresolver.cpp \
    ../Common/netlinkmanager.cpp \
    ../Common/packsreceiver.cpp \
    ../Common/dbmanager.cpp \
    ../PST/pst_node.cpp \
    ../PST/pst_context.cpp \
    ../PST/pst_builder.cpp \
    ../PST/pst_arithpredictor.cpp \
    ../PST/pst_samples.cpp \
    ../PST/pst_predictor.cpp \
    ../SOM/neuron.cpp \
    ../SOM/samplesom.cpp \
    ../SOM/selforganizedmap.cpp \
    ../Common/utils/ConfigReader.cpp \
    ../Common/utils/DaemonService.cpp \
    ../Common/utils/NullLogger.cpp \
    ../Common/utils/LowLevelThread.cpp \
    ../Common/utils/LowLevelSocket.cpp \
    ../Common/utils/Logger.cpp \
    ../Common/utils/Service.cpp \
    ../Common/utils/Semaphore.cpp \
    ../Common/utils/PrintfLogger.cpp \
    ../Common/utils/PosixThread.cpp \
    ../Common/utils/Pool.cpp \
    ../Common/utils/PlatformFactory.cpp \
    ../Common/utils/UnixSemaphore.cpp \
    ../Common/utils/UnixLowLevelSocket.cpp \
    ../Common/utils/Thread.cpp \
    ../Common/utils/SyslogLogger.cpp \
    ../Common/utils/SocketSignal.cpp \
    ../Common/utils/Signal.cpp \
    ../Common/ConnectionTree.cpp \
    anomaly_frame.cpp \
    ads_settings_dialog.cpp \
    anomaly_reader_tcp.cpp \
    learning_tcp_dialog.cpp \
    learning_flow_dialog.cpp \
    anomaly_reader_flow.cpp

HEADERS  += mainwindow.h \
    ../Common/utils/StdThread.h \
    rulesform.h \
    addruleform.h \
    ../Common/adressresolver.h \
    ../Common/netlinkmanager.h \
    ../Common/packsreceiver.h \
    ../Common/dbmanager.h \
    ../PST/pst_node.h \
    ../PST/pst_context.h \
    ../PST/pst_common.h \
    ../PST/pst_builder.h \
    ../PST/pst_arithpredictor.h \
    ../PST/pst_samples.h \
    ../PST/pst_predictor.h \
    ../SOM/neuron.h \
    ../SOM/samplesom.h \
    ../SOM/selforganizedmap.h \
    ../Common/utils/DaemonService.h \
    ../Common/utils/NullLogger.h \
    ../Common/utils/LowLevelThread.h \
    ../Common/utils/LowLevelSocket.h \
    ../Common/utils/Logger.h \
    ../Common/utils/Service.h \
    ../Common/utils/Semaphore.h \
    ../Common/utils/PrintfLogger.h \
    ../Common/utils/PosixThread.h \
    ../Common/utils/Pool.h \
    ../Common/utils/PlatformFactory.h \
    ../Common/utils/UnixSemaphore.h \
    ../Common/utils/UnixLowLevelSocket.h \
    ../Common/utils/Thread.h \
    ../Common/utils/SyslogLogger.h \
    ../Common/utils/SocketSignal.h \
    ../Common/utils/Signal.h \
    ../Common/rb_connection_tree.h \
    ../Common/ConnectionTree.h \
    ../Common/structs.h \
    anomaly_frame.h \
    ads_settings_dialog.h \
    anomaly_reader_tcp.h \
    learning_tcp_dialog.h \
    learning_flow_dialog.h \
    anomaly_reader_flow.h

FORMS    += mainwindow.ui \
    rulesform.ui \
    addruleform.ui \
    ads_settings_dialog.ui \
    learning_tcp_dialog.ui \
    learning_flow_dialog.ui

QMAKE_CXXFLAGS = -g
QMAKE_CFLAGS = -g


#QMAKE_CXXFLAGS = -I/usr/src/linux-headers-3.5.0-17-generic/include/
#QMAKE_CFLAGS = -I/usr/src/linux-headers-3.5.0-17-generic/include/

OTHER_FILES += \
    http.samples \
    https.samples \
    ftp.samples \
    ssh.samples \
    telnet.samples \
    common.samples \
    flow.samples \
    ads.settings
