####### Compiler, tools and options

CC            = gcc
CXX           = g++
DEFINES       = 
CFLAGS        = -pipe -O2 -Wall -W -D_REENTRANT $(DEFINES)
CXXFLAGS      = -pipe -O2 -Wall -W -D_REENTRANT $(DEFINES)
INCPATH       = -I. -I../Common/utils -I.
LINK          = g++
LFLAGS        = -Wl,-O1
LIBS          = -L/usr/lib -lpthread 
AR            = ar cqs
RANLIB        = 
QMAKE         = /usr/bin/qmake
TAR           = tar -cf
COMPRESS      = gzip -9f
COPY          = cp -f
SED           = sed
COPY_FILE     = $(COPY)
COPY_DIR      = $(COPY) -r
STRIP         = strip
INSTALL_FILE  = install -m 644 -p
INSTALL_DIR   = $(COPY_DIR)
INSTALL_PROGRAM = install -m 755 -p
DEL_FILE      = rm -f
SYMLINK       = ln -f -s
DEL_DIR       = rmdir
MOVE          = mv -f
CHK_DIR_EXISTS= test -d
MKDIR         = mkdir -p

####### Output directory

OBJECTS_DIR   = ./

####### Files

SOURCES       = ads_drvctl.cpp \
		../Common/utils/PrintfLogger.cpp \
		../Common/utils/Logger.cpp \
		../Common/utils/ConfigReader.cpp 
OBJECTS       = ads_drvctl.o \
		PrintfLogger.o \
		Logger.o \
		ConfigReader.o
QMAKE_TARGET  = ads_drvctl
DESTDIR       = 
TARGET        = ads_drvctl

first: all
####### Implicit rules

.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.cc.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.cxx.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.C.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(INCPATH) -o "$@" "$<"

####### Build rules

all: Makefile $(TARGET)

$(TARGET):  $(OBJECTS)  
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

qmake:  FORCE
	@$(QMAKE) -unix -o Makefile ads_drvctl.pro

dist: 
	@$(CHK_DIR_EXISTS) .tmp/ads_drvctl1.0.0 || $(MKDIR) .tmp/ads_drvctl1.0.0 
	$(COPY_FILE) --parents $(SOURCES) $(DIST) .tmp/ads_drvctl1.0.0/ && $(COPY_FILE) --parents ../Common/utils/PrintfLogger.h ../Common/utils/Logger.h ../Common/utils/ConfigReader.h .tmp/ads_drvctl1.0.0/ && $(COPY_FILE) --parents ads_drvctl.cpp ../Common/utils/PrintfLogger.cpp ../Common/utils/Logger.cpp ../Common/utils/ConfigReader.cpp .tmp/ads_drvctl1.0.0/ && (cd `dirname .tmp/ads_drvctl1.0.0` && $(TAR) ads_drvctl1.0.0.tar ads_drvctl1.0.0 && $(COMPRESS) ads_drvctl1.0.0.tar) && $(MOVE) `dirname .tmp/ads_drvctl1.0.0`/ads_drvctl1.0.0.tar.gz . && $(DEL_FILE) -r .tmp/ads_drvctl1.0.0


clean:compiler_clean 
	-$(DEL_FILE) $(OBJECTS)
	-$(DEL_FILE) *~ core *.core


####### Sub-libraries

distclean: clean
	-$(DEL_FILE) $(TARGET) 
	-$(DEL_FILE) Makefile


mocclean: compiler_moc_header_clean compiler_moc_source_clean

mocables: compiler_moc_header_make_all compiler_moc_source_make_all

compiler_moc_header_make_all:
compiler_moc_header_clean:
compiler_rcc_make_all:
compiler_rcc_clean:
compiler_image_collection_make_all: qmake_image_collection.cpp
compiler_image_collection_clean:
	-$(DEL_FILE) qmake_image_collection.cpp
compiler_moc_source_make_all:
compiler_moc_source_clean:
compiler_uic_make_all:
compiler_uic_clean:
compiler_yacc_decl_make_all:
compiler_yacc_decl_clean:
compiler_yacc_impl_make_all:
compiler_yacc_impl_clean:
compiler_lex_make_all:
compiler_lex_clean:
compiler_clean: 

####### Compile

ads_drvctl.o: ads_drvctl.cpp 
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o ads_drvctl.o ads_drvctl.cpp

PrintfLogger.o: ../Common/utils/PrintfLogger.cpp ../Common/utils/PrintfLogger.h \
		../Common/utils/Logger.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o PrintfLogger.o ../Common/utils/PrintfLogger.cpp

Logger.o: ../Common/utils/Logger.cpp ../Common/utils/Logger.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o Logger.o ../Common/utils/Logger.cpp

ConfigReader.o: ../Common/utils/ConfigReader.cpp ../Common/utils/ConfigReader.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o ConfigReader.o ../Common/utils/ConfigReader.cpp

####### Install

install:   FORCE

uninstall:   FORCE

FORCE:

