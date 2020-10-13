   
#your Ida SDK location either relative to x86emu
#or absolute
SDK = ../..

OBJECTS_DIR = p32-7

#Need to change the following to your Ida install location
linux-g++:IDA_APP = /opt/ida-$$(IDA_VERSION)
macx:IDA_APP = "/Applications/IDA\ Pro\ $$(IDA_VERSION)/ida.app/Contents"

#Need to change the following to your Qt install location
macx: {
   greaterThan(QT_MAJOR_VERSION, 4):QT_LOC = /Users/qt-5.4.1/5.4/clang_64/lib
   lessThan(QT_MAJOR_VERSION, 5):QT_LOC = /usr/local/qt/lib
   QT_TAIL = .framework/Versions/$$QT_MAJOR_VERSION/Headers
   #create our own list of Qt modules
   MODS = QtGui QtCore
   greaterThan(QT_MAJOR_VERSION, 4):MODS += QtWidgets
}

defineReplace(makeIncludes) {
   variable = $$1
   modules = $$eval($$variable)
   dirs =
   for(module, modules) {
      dir = $${QT_LOC}/$${module}$${QT_TAIL}
      dirs += $$dir
   }
   return($$dirs)
}

TEMPLATE = lib

greaterThan(QT_MAJOR_VERSION, 4):QT += widgets

CONFIG += qt dll

INCLUDEPATH += $${SDK}/include

DESTDIR = bin

DEFINES += __IDP__ __QT__ __X64__
win32:DEFINES += __NT__ WIN32
win32:DEFINES -= UNICODE
win32:DEFINES += _CRT_SECURE_NO_WARNINGS
win32:QMAKE_TARGET.arch = x86_64
linux-g++:DEFINES += __LINUX__
macx:DEFINES += __MAC__

win32:LIBS += comdlg32.lib gdi32.lib user32.lib advapi32.lib ida.lib ws2_32.lib
win32-msvc2013: {
   exists( $${SDK}/lib/vc.w64/ida.lib ) {
      LIBS += -L$${SDK}/lib/vc.w64
   } else {
      LIBS += -L$${SDK}/lib/x64_win_vc_32
      LIBS += -L$${SDK}/lib/x64_win_qt
   }
   QMAKE_LFLAGS_RPATH =
   QMAKE_LIBDIR_QT =
}
linux-g++:LIBS += -L$${IDA_APP} -lida
macx:LIBS += -L$${IDA_APP}/MacOs -lida

#don't let qmake force search any libs other than the
#ones that ship with Ida
linux-g++:QMAKE_LFLAGS_RPATH =
linux-g++:QMAKE_LIBDIR_QT =

macx:QMAKE_INCDIR = $$makeIncludes(MODS)
#add QTs actual include file location this way since -F is not
#handled by QMAKE_INCDIR
macx:QMAKE_CXXFLAGS += -m64 -F$${QT_LOC} -stdlib=libc++

linux-g++:QMAKE_CXXFLAGS = -m64

SDKVER = $$(IDAVER)
linux-g++|macx: {
   QMAKE_CXXFLAGS += -m64
   QMAKE_CFLAGS += -m64
   QMAKE_LFLAGS += -m64
   greaterThan(SDKVER, 720):QMAKE_CXXFLAGS += -std=c++11
}

macx:QMAKE_LFLAGS += -F$${IDA_APP}/Frameworks
macx:QMAKE_LIBDIR_QT =
macx:QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.9

SOURCES = x86emu.cpp \
   x86emu_ui_qt.cpp \
   emufuncs.cpp \
   cpu.cpp \
   emuheap.cpp \
   memmgr.cpp \
   seh.cpp \
   break.cpp \
   hooklist.cpp \
   buffer.cpp \
   emuthreads.cpp \
   peutils.cpp \
   emu_script.cpp \
   context.cpp \
   aes.cpp \
   ansi_cprng.cpp

HEADERS = aes.h \
   ansi_cprng.h \
   break.h \
   bsd_syscalls.h \
   buffer.h \
   cgc_syscalls.h \
   context.h \
   cpu.h \
   elf32.h \
   elf_common.h \
   emu_script.h \
   emufuncs.h \
   emuheap.h \
   emuthreads.h \
   hooklist.h \
   image.h \
   linux_syscalls.h \
   memmgr.h \
   peutils.h \
   sdk_versions.h \
   seh.h \
   x86emu_ui_qt.h \
   x86defs.h

win32:TARGET_EXT=.dll
linux-g++:TARGET_EXT=.so
macx:TARGET_EXT=.dylib

TARGET = x86emu_qt
