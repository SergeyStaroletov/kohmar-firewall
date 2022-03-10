SOURCES += tcdrvctl.cpp \
    ../common_src/utils/PrintfLogger.cpp \
    ../common_src/utils/Logger.cpp \
    ../common_src/utils/ConfigReader.cpp
HEADERS += ../common_src/utils/PrintfLogger.h \
    ../common_src/utils/Logger.h \
    ../common_src/utils/ConfigReader.h \

INCLUDEPATH += ../common_src/utils

#libs include

LIBS += -lpthread

QT -= gui
QT -= core
LIBS   -= -lQtGui -lQtCore

