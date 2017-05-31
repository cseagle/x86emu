/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2010 Chris Eagle
   
   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the Free
   Software Foundation; either version 2 of the License, or (at your option) 
   any later version.
   
   This program is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
   FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for 
   more details.
   
   You should have received a copy of the GNU General Public License along with 
   this program; if not, write to the Free Software Foundation, Inc., 59 Temple 
   Place, Suite 330, Boston, MA 02111-1307 USA
*/

#ifndef __X86EMU_QT_H__
#define __X86EMU_QT_H__

#ifdef __QT__
#ifndef QT_NAMESPACE
#define QT_NAMESPACE QT
#endif
#endif

#include <QtGui>
#include <QDialog>
#include <QListWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QMainWindow>
#include <QRadioButton>
#include <QValidator>
#include <QSpinBox>
#include <QPushButton>
#include <QAction>

#include "x86defs.h"
#include "x86emu_ui.h"

using namespace QT;

class AllIntValidator : public QValidator {
   Q_OBJECT
public:
   AllIntValidator(QObject *parent = 0) : QValidator(parent) {}
   State validate(QString &input, int &pos) const;
};

class X86Dialog : public QMainWindow {
   Q_OBJECT
public:
   X86Dialog(QWidget *parent = 0);
public slots:
   void changeEax();
   void changeEbx();
   void changeEcx();
   void changeEdx();
   void changeEbp();
   void changeEsp();
   void changeEdi();
   void changeEsi();
   void changeEip();
   void changeEflags();
   void settings();
   void dumpRange();
   void dumpEmbededPE();
   void grabStackBlock();
   void grabHeapBlock();
   void grabMmapBlock();
   void buildMainArgs();
   void buildWinMainArgs();
   void buildDllMainArgs();
   void reset();
   void trackExec();
   void traceExec();
   void logLibraryCalls();
   void breakOnExceptions();
   void breakOnSyscall();
   void logSystemCalls();
   void setImportAddressSavePoint();
   void setBreak();
   void clearBreak();
   void memoryException();
   void exportLookup();
   void switchThreads();
   void hideEmu();
   void heapList();
   void step();
   void skip();
   void run();
   void doBreak();
   void runCursor();
   void jumpCursor();
   void pushData();
   void setMemory();
   void segments();
   void loadLibrary();
   
public:
   QLineEdit *QEAX;
   QLineEdit *QEBX;
   QLineEdit *QECX;
   QLineEdit *QEDX;
   QLineEdit *QEFLAGS;
   QLineEdit *QEBP;
   QLineEdit *QESP;
   QLineEdit *QESI;
   QLineEdit *QEDI;
   QLineEdit *QEIP;
private:
   QAction *emulateTrack_fetched_bytesAction;
   QAction *emulateTrace_executionAction;
   QAction *emulateLogLibraryAction;
   QAction *emulateBreakOnExceptionsAction;
   QAction *emulateBreakSyscallAction;
   QAction *emulateLogSyscallsAction;
   QPushButton *BREAK;
};

class SegmentsDialog : public QDialog {
   Q_OBJECT
public:
   SegmentsDialog(QWidget *parent = 0);

public:
   QLineEdit *qcs_reg;
   QLineEdit *qgs_reg;
   QLineEdit *qss_reg;
   QLineEdit *qds_reg;
   QLineEdit *qes_reg;
   QLineEdit *qfs_reg;
   QLineEdit *qds_base;
   QLineEdit *qcs_base;
   QLineEdit *qgs_base;
   QLineEdit *qfs_base;
   QLineEdit *qss_base;
   QLineEdit *qes_base;
   
private slots:
   void do_ok();
};

class MemConfigDialog : public QDialog {
   Q_OBJECT
public:
   MemConfigDialog(QWidget *parent = 0);
   QLineEdit *heap_base;
   QLineEdit *heap_size;
   QLineEdit *stack_top;
   QLineEdit *stack_size;
private slots:
   void do_ok();
};

class UnemulatedDialog : public QDialog {
   Q_OBJECT
public:
   UnemulatedDialog(QWidget *parent, const char *name, unsigned int addr);
   const char *fname;
   char *functionCall;
   
public:
   QRadioButton *is_cdecl;
   QRadioButton *is_stdcall;
   QPushButton *ue_okay;
   QSpinBox *ue_args;
   QLineEdit *ue_return;
   QListWidget *parm_list;

private slots:
   void do_ok();
};

class ThreadsDialog : public QDialog {
   Q_OBJECT
public:
   QListWidget *thread_list;

   ThreadsDialog(QWidget *parent = 0);

private slots:
   void switchThread();
   void destroy();
};

class MmapDialog : public QDialog {
   Q_OBJECT
public:
   MmapDialog(QWidget *parent = 0);

   QLineEdit *mmap_base;
   QLineEdit *mmap_size;

private slots:
   void do_ok();
};

class SetMemoryDialog : public QDialog {
   Q_OBJECT
public:
   SetMemoryDialog(QWidget *parent = 0);
   QRadioButton *type_dword;
   QRadioButton *type_word;
   QRadioButton *type_byte;
   QRadioButton *type_ascii;
   QRadioButton *type_asciiz;
   QRadioButton *type_file;
   QLineEdit *mem_start;
   QLineEdit *mem_values;

private slots:
   void do_ok();
};

#endif
