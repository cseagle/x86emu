/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2003-2010 Chris Eagle
   
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

/*
 *  This is the x86 Emulation plugin module
 *
 *  It is known to compile with
 *
 *  - Qt Version: Windows - Visual Studio 2008, Linux/OS X - g++
 *  - Windows only version (IDA < 6.0): Visual C++ 6.0, Visual Studio 2005, MinGW g++/make
 *
 */

#ifdef PACKED
#undef PACKED
#endif

#ifdef __QT__
#ifndef QT_NAMESPACE
#define QT_NAMESPACE QT
#endif
#endif

#include <QtGlobal>
#if QT_VERSION >= 0x050000
#define toAscii toLatin1
#endif

#include <QApplication>
#include <QMessageBox>
#include <QToolBar>
#include <QButtonGroup>
#include <QFileDialog>
#include <QInputDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QGroupBox>
#include <QFormLayout>
#include <QMenu>

#include "x86emu_ui_qt.h"

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <auto.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <segment.hpp>
#include <typeinf.hpp>
#include <struct.hpp>

#include "cpu.h"
#include "emufuncs.h"
#include "emuthreads.h"

QWidget *mainWindow;
X86Dialog *x86Dlg;

void cacheMainWindowHandle() {
   if (mainWindow == NULL) {
      mainWindow = QApplication::activeWindow();
   }
}

QValidator::State AllIntValidator::validate(QString &input, int & /*pos*/) const {
   char *endptr;
   QByteArray qba = input.toAscii(); 
   char *nptr = qba.data();
   if (*nptr == 0 || stricmp("0x", nptr) == 0) {
      return Intermediate;
   }
   strtoul(nptr, &endptr, 0);
   if (*nptr && !*endptr) {
      return Acceptable;
   }
   return Invalid;
}

AllIntValidator aiv;

//QFont fixed;

QWidget *getWidgetParent() {
   if (mainWindow == NULL) {
      mainWindow = QApplication::activeWindow();
   }
   return mainWindow;
}

extern til_t *ti;

/*
 * Set the title of the emulator window
 */
void setEmulatorTitle(const char *title) {
   x86Dlg->setWindowTitle(title);
}

//convert a register number into a control ID for the register's display
QLineEdit *regToControl(unsigned int reg) {
   switch (reg) {
      case EAX:
         return x86Dlg->QEAX;
      case EBX:
         return x86Dlg->QEBX;
      case ECX:
         return x86Dlg->QECX;
      case EDX:
         return x86Dlg->QEDX;
      case ESP:
         return x86Dlg->QESP;
      case EBP:
         return x86Dlg->QEBP;
      case ESI:
         return x86Dlg->QESI;
      case EDI:
         return x86Dlg->QEDI;
      case EIP:
         return x86Dlg->QEIP;
      case EFLAGS:
         return x86Dlg->QEFLAGS;
   }
   return NULL;
}

//update the specified register display with the specified 
//value. Useful for updating register contents based on user
//input
void updateRegisterDisplay(int r) {
   static bool registersSet[MAX_REG + 1];
   static unsigned int current[MAX_REG + 1];
   QLineEdit *l = regToControl(r);
   if (l) {
      char buf[16];
      unsigned int rval = getRegisterValue(r);
      ::qsnprintf(buf, sizeof(buf), "0x%08X", rval);
      QString v(buf);
      if (registersSet[r]) {
         if (rval != current[r]) {
            current[r] = rval;
            l->setStyleSheet("QLineEdit{color: red;}");
         }
         else {
            l->setStyleSheet("QLineEdit{color: black;}");
         }
      }
      else {
         registersSet[r] = true;
         current[r] = rval;
      }
      l->setText(v);
   }
}

/*
//update the specified register display with the specified 
//value.  useful to update register contents based on user
//input
void updateRegisterControl(int controlID) {
   char buf[16];
   unsigned int *reg = controlToRegPtr(controlID);
   if (reg) {
      ::qsnprintf(buf, sizeof(buf), "0x%08X", *reg);
      SetDlgItemText(x86Dlg, controlID, buf);
   }
}
*/

//get an int value from edit box string
//assumes value is a valid hex string
unsigned int getEditBoxInt(QLineEdit *l) {
   return strtoul(l->text().toAscii().data(), NULL, 0);
}

//display a single line input box with the given title, prompt
//and initial data value.  If the user does not cancel, their
//data is placed into the global variable "value"
char *inputBox(const char *boxTitle, const char *msg, const char *init) {
   static char value[80]; //value entered by the user
   bool ok;
   QString text = QInputDialog::getText(getWidgetParent(), boxTitle,
                              msg, QLineEdit::Normal, init, &ok);
   if (ok && !text.isEmpty()) {
      ::qstrncpy(value, text.toAscii().data(), sizeof(value));
      return value;
   }
   return NULL;
}

/*
//respond to a double click on one of the register
//edit controls, by asking the user for a new
//value for that register
void doubleClick(HWND edit) {
   int idx = 0;
   while (editBoxes[idx] != edit) idx++;
   int ctl = IDC_EAX + idx;
   unsigned int *reg = controlToRegPtr(ctl);
   if (reg) {
      char message[32] = "Enter new value for ";
      char original[16];
      qstrncat(message, names[idx], sizeof(message));
      ::qsnprintf(original, sizeof(original), "0x%08X", *reg);
      char *v = inputBox("Update register", message, original);
      if (v) {
         *reg = strtoul(v, NULL, 0);
         updateRegisterControl(ctl);
      }
   }
}
*/

char *getSaveFileName(const char *title, char *fileName, int nameSize, const char *filter) {
   if (fileName == NULL || nameSize == 0) {
      return NULL;
   }
   QString f = QFileDialog::getSaveFileName(getWidgetParent(), title,
                                            QString(), filter);
   if (!f.isNull()) {
      QByteArray qba = f.toAscii();
      ::qstrncpy(fileName, qba.data(), nameSize);
      return fileName;
   }
   return NULL;
}

char *getDirectoryName(const char *title, char *dirName, int nameSize) {
   if (dirName == NULL || nameSize == 0) {
      return NULL;
   }

   QString dir = QFileDialog::getExistingDirectory(getWidgetParent(), title,
                                                 QString(), QFileDialog::ShowDirsOnly
                                                 | QFileDialog::DontResolveSymlinks);   
   
   if (!dir.isNull()) {
      QByteArray qba = dir.toAscii();
      ::qstrncpy(dirName, qba.data(), nameSize);
      return dirName;
   }
   return NULL;
}

void showErrorMessage(const char *msg) {
   QMessageBox::warning(getWidgetParent(), "Error", msg);
}

void argCallback(const char * /*func*/, const char *arg, int idx, void *user) {
   UnemulatedDialog *ud = (UnemulatedDialog*)user;
   ud->parm_list->addItem(arg);

   if (doLogLib) {
      int len = strlen(arg);
      if (arg[len - 1] == '\'') {
         const char *s = strchr(arg, '\'');
         size_t flen = strlen(ud->functionCall) + strlen(s) + 5;
         ud->functionCall = (char*)qrealloc(ud->functionCall, flen);
         if (idx > 0) {
            ::qstrncat(ud->functionCall, "\x01 ", flen);
         }
         ::qstrncat(ud->functionCall, s, flen);
      }
      else {
         const char *s = strstr(arg, "0x");
         size_t fend = strlen(ud->functionCall);
         size_t flen = fend + 15;
         ud->functionCall = (char*)qrealloc(ud->functionCall, flen);
         if (idx > 0) {
            ::qstrncat(ud->functionCall, "\x01 ", flen);
            fend += 2;
         }
         memcpy(ud->functionCall + fend, s, 10);
         ud->functionCall[fend + 10] = 0;
      }
   }
}

void UnemulatedDialog::do_ok() {
   unsigned int retval = 0;
   QByteArray _v = ue_return->text().toAscii();
   char *value = _v.data();
   retval = strtoul(value, NULL, 0);
   eax = retval;

   unsigned int stackfree = ue_args->value();
   unsigned int callType = 0xFFFFFFFF;
   if (is_cdecl->isChecked()) {
      callType = CALL_CDECL;
   }
   else if (is_stdcall->isChecked()) {
      callType = CALL_STDCALL;
   }
   else {
      showErrorMessage("Please select a calling convention.");
   }
   if (callType != 0xFFFFFFFF) {
      addFunctionInfo(fname, retval, stackfree, callType);
      if (callType == CALL_STDCALL) {
         esp += stackfree * 4;
      }
      accept();
      if (doLogLib) {
         char *p = strchr(functionCall, '(') + 1;
         for (unsigned int i = 0; i < stackfree; i++) {
            char *n = strchr(p, 1);
            if (n) {
               p = n;
               *p = ',';
            }
            else {
               p = functionCall + strlen(functionCall);
            }
         }
         *p++ = ')';
         *p = 0;
         msg("call: %s = 0x%x\n", functionCall, eax);
         qfree(functionCall);
         functionCall = NULL;
      }
   }
}

UnemulatedDialog::UnemulatedDialog(QWidget *parent, const char *name, unsigned int addr) : QDialog(parent) {
   char buf[256];
   fname = name;
   functionCall = NULL;
   if (name) {
      ::qsnprintf(buf, sizeof(buf), "Call to: %s", name);
      if (doLogLib) {
         size_t sz = strlen(fname) + 5;
         functionCall = (char*)qalloc(sz);
         ::qsnprintf(functionCall, sz, "%s(", fname);
      }
   }
   else {
      ::qsnprintf(buf, sizeof(buf), "Call to: Location 0x%08x", addr);
      if (doLogLib) {
         functionCall = (char*)qalloc(14);
         ::qsnprintf(functionCall, 14, "0x%08x(", addr);
      }
   }
   setWindowTitle(buf);
   
   setModal(true);

   QVBoxLayout *mainLayout = new QVBoxLayout();
   mainLayout->setSpacing(2);
   mainLayout->setContentsMargins(4, 4, 4, 4);

   QLabel *argLabel = new QLabel("Arguments");
   parm_list = new QListWidget();
   parm_list->setSortingEnabled(false);
   QFont font1;
   font1.setFamily("Courier");
   parm_list->setFont(font1);

   argLabel->setBuddy(parm_list);
   mainLayout->addWidget(argLabel);
   mainLayout->addWidget(parm_list);

   QLabel *returnLabel = new QLabel("Return type: unknown");

   is_cdecl = new QRadioButton("cdecl");
   is_stdcall = new QRadioButton("stdcall");
   
   QVBoxLayout *vbl = new QVBoxLayout();
   vbl->setSpacing(2);
   vbl->setContentsMargins(4, 4, 4, 4);

   vbl->addWidget(is_cdecl);
   vbl->addWidget(is_stdcall);

   QGroupBox *gb = new QGroupBox("Calling convention");
   gb->setLayout(vbl);
   
   ue_okay = new QPushButton("Ok");

   ue_args = new QSpinBox();
   ue_args->setRange(0, 100);
   ue_args->setSuffix(" arguments");
   
   ue_return = new QLineEdit("0x00000000");
   ue_return->setValidator(&aiv);
   
   QFormLayout *fl = new QFormLayout();
   fl->setSpacing(2);
   fl->setContentsMargins(4, 4, 4, 4);
   fl->addRow("Return value (eax)", ue_return);
   fl->addRow("Number of args", ue_args);
   
   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addLayout(fl);
   hbl->addWidget(gb);
   
   mainLayout->addWidget(returnLabel);
   mainLayout->addLayout(hbl);
   
   generateArgList(name, argCallback, this);

   int len = 8;
   FunctionInfo *f = getFunctionInfo(name);
   if (f) {
      len = f->stackItems;
      ::qsnprintf(buf, sizeof(buf), "0x%8.8x", f->result);
      ue_return->setText(buf);
      ue_args->setValue(f->stackItems);
      if (f->callingConvention == CALL_CDECL) {
         is_cdecl->setChecked(true);
      }
      else {
         is_stdcall->setChecked(true);
      }
      char *ret_type = getFunctionReturnType(f);

      if (ret_type) {
         ::qsnprintf(buf, sizeof(buf), "Return type: %s", ret_type);
         returnLabel->setText(buf);
         free(ret_type);
      }
   }

   connect(ue_okay, SIGNAL(clicked()), this, SLOT(do_ok()));   

   QHBoxLayout *hb = new QHBoxLayout();
   hb->setSpacing(2);
   hb->setContentsMargins(4, 4, 4, 4);
   hb->addStretch(1);
   hb->addWidget(ue_okay);
   hb->addStretch(1);
   
   mainLayout->addLayout(hb);
   
   setLayout(mainLayout);
}

/*
 * This function is used for all unemulated API functions
 */
void handleUnemulatedFunction(unsigned int addr, const char *name) {
   UnemulatedDialog ud(getWidgetParent(), name, addr);
   ud.exec();
   shouldBreak = 1;
}

void ThreadsDialog::switchThread() {
   int selected = thread_list->currentRow();
   ::switchThread(selected);
   accept();
}

void ThreadsDialog::destroy() {
   int selected = thread_list->currentRow();
   destroyThread(selected);
   accept();
}

/*
 * Ask the user which thread they would like to switch to
 * and make the necessary changes to the cpu state.
 */
ThreadsDialog::ThreadsDialog(QWidget *parent) : QDialog(parent) {
   char buf[128];
   setModal(true);
   QLabel *textLabel = new QLabel("Current threads");

   thread_list = new QListWidget();
   textLabel->setBuddy(thread_list);

   QPushButton *threads_cancel = new QPushButton("&Cancel");
   QPushButton *threads_destroy = new QPushButton("&Destroy");
   QPushButton *threads_switch = new QPushButton("&Switch");
   
   for (ThreadNode *tn = threadList; tn; tn = tn->next) {
      ::qsnprintf(buf, sizeof(buf), "Thread 0x%x%s", tn->handle, tn->next ? "" : " (main)");
      thread_list->addItem(buf);
   }

   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->setSpacing(2);
   buttonLayout->setContentsMargins(4, 4, 4, 4);
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(threads_switch);
   buttonLayout->addWidget(threads_destroy);
   buttonLayout->addWidget(threads_cancel);
   buttonLayout->addStretch(1);
   
   QWidget *buttons = new QWidget();
   buttons->setLayout(buttonLayout);
   
   QVBoxLayout *mainLayout = new QVBoxLayout;
   mainLayout->setSpacing(2);
   mainLayout->setContentsMargins(4, 4, 4, 4);
   mainLayout->addWidget(textLabel);
   mainLayout->addWidget(thread_list);
   mainLayout->addWidget(buttons);
   setLayout(mainLayout);
   
   connect(threads_switch, SIGNAL(clicked()), this, SLOT(switchThread()));
   connect(threads_cancel, SIGNAL(clicked()), this, SLOT(reject()));
   connect(threads_destroy, SIGNAL(clicked()), this, SLOT(destroy()));
   
   setWindowTitle("Manage Threads");
}

void MemConfigDialog::do_ok() {
/*
   mgr->initStack(getEditBoxInt(hwndDlg, IDC_STACKTOP), 
                  getEditBoxInt(hwndDlg, IDC_STACKSIZE));
   esp = mgr->stack->getStackTop();
   unsigned int heapSize = getEditBoxInt(hwndDlg, IDC_HEAPSIZE);
   if (heapSize) {
      mgr->initHeap(getEditBoxInt(hwndDlg, IDC_HEAPBASE), heapSize);
   }
   SendDlgItemMessage(x86Dlg, IDC_MEMORY, LB_RESETCONTENT, 0, 0);
   listTop = mgr->stack->getStackTop() - 1;
   syncDisplay();
*/
   accept();
}

MemConfigDialog::MemConfigDialog(QWidget *parent) : QDialog(parent) {
   setSizeGripEnabled(false);
   setModal(true);

   heap_base = new QLineEdit();
   heap_base->setValidator(&aiv);
   heap_size = new QLineEdit();
   heap_size->setValidator(&aiv);
   stack_top = new QLineEdit();
   stack_top->setValidator(&aiv);
   stack_size = new QLineEdit();
   stack_size->setValidator(&aiv);

   char buf[16];
   segment_t *s = get_segm_by_name(".stack");
   segment_t *h = get_segm_by_name(".heap");
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)s->endEA);
   stack_top->setText(buf);
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)(s->endEA - s->startEA));
   stack_size->setText(buf);
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)h->startEA);
   heap_base->setText(buf);
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)(h->endEA - h->startEA));
   heap_size->setText(buf);

   QFormLayout *fl = new QFormLayout();
   fl->setSpacing(2);
   fl->setContentsMargins(4, 4, 4, 4);
   fl->addRow("Stack top address", stack_top);
   fl->addRow("Max stack size", stack_size);
   fl->addRow("Heap base address", heap_base);
   fl->addRow("Max heap size", heap_size);

   QWidget *form = new QWidget();
   form->setLayout(fl);

   QHBoxLayout *hboxLayout = new QHBoxLayout();
   hboxLayout->setSpacing(2);
   hboxLayout->setContentsMargins(4, 4, 4, 4);

   QPushButton *buttonOk = new QPushButton("&OK");
   buttonOk->setAutoDefault(true);
   buttonOk->setDefault(true);
   
   QPushButton *buttonCancel = new QPushButton("&Cancel");
   buttonCancel->setAutoDefault(true);
   
   hboxLayout->addStretch(1);
   hboxLayout->addWidget(buttonOk);   
   hboxLayout->addWidget(buttonCancel);
   hboxLayout->addStretch(1);

   QWidget *buttons = new QWidget();
   buttons->setLayout(hboxLayout);

   QVBoxLayout *vbl = new QVBoxLayout();
   vbl->setSpacing(2);
   vbl->setContentsMargins(4, 4, 4, 4);
   
   vbl->addWidget(form);
   vbl->addWidget(buttons);
   
   setLayout(vbl);
      
   connect(buttonOk, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(buttonCancel, SIGNAL(clicked()), this, SLOT(reject()));
   
   setWindowTitle("Memory Layout");

}

//ask user for an file name and load the file into memory
//at the specified address
char *getOpenFileName(const char *title, char *fileName, int nameLen, const char *filter, char *initDir) {
   if (fileName == NULL || nameLen == 0) {
      return NULL;
   }
   QString f = QFileDialog::getOpenFileName(getWidgetParent(), title,
                                            initDir, filter);
   if (!f.isNull()) {
      QByteArray qba = f.toAscii();
      ::qstrncpy(fileName, qba.data(), nameLen);
      return fileName;
   }
   return NULL;
}

static void setMemValues(unsigned int addr, const char *v, unsigned int sz) {
   char *ptr;
   while ((ptr = (char*)strchr(v, ' ')) != NULL) {
      *ptr++ = 0;
      if (strlen(v)) {
         writeMem(addr, strtoul(v, NULL, 16), sz);
         addr += sz;
      }
      v = ptr;
   }
   if (strlen(v)) {
      writeMem(addr, strtoul(v, NULL, 16), sz);
   }
}

void SetMemoryDialog::do_ok() {
   QByteArray a = mem_start->text().toAscii();
   const char *ea = a.data();
   unsigned int addr = strtoul(ea, 0, 0);
   QByteArray t = mem_values->text().toAscii();
   const char *v = t.data();

   if (type_file->isChecked()) {
      memLoadFile(addr);
   }
   else if (type_byte->isChecked()) {
      setMemValues(addr, v, SIZE_BYTE);
   }
   else if (type_word->isChecked()) {
      setMemValues(addr, v, SIZE_WORD);
   }
   else if (type_dword->isChecked()) {
      setMemValues(addr, v, SIZE_DWORD);
   }
   else if (type_ascii->isChecked() || type_asciiz->isChecked()) {
      while (*v) {
         writeMem(addr++, *v++, SIZE_BYTE);
      }
      if (type_asciiz->isChecked()) writeMem(addr, 0, SIZE_BYTE);
   }
   accept();
}

SetMemoryDialog::SetMemoryDialog(QWidget *parent) : QDialog(parent) {
   setSizeGripEnabled(false);
   setModal(true);

   QLabel *address = new QLabel("Start address:");
   QLabel *values = new QLabel("Space separated values:");

   QPushButton *set_ok = new QPushButton("&OK");
   set_ok->setAutoDefault(true);
   set_ok->setDefault(true);
   
   QPushButton *set_cancel = new QPushButton("&Cancel");
   set_cancel->setAutoDefault(true);
   
   QHBoxLayout *buttonLayout = new QHBoxLayout();
   buttonLayout->setSpacing(2);
   buttonLayout->setContentsMargins(4, 4, 4, 4);
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(set_ok);
   buttonLayout->addWidget(set_cancel);
   buttonLayout->addStretch(1);
   
   QWidget *buttonPanel = new QWidget();
   buttonPanel->setLayout(buttonLayout);
   
   type_dword = new QRadioButton("32 bit hex");
   type_word = new QRadioButton("16 bit hex");
   type_byte = new QRadioButton("8 bit hex");
   type_ascii = new QRadioButton("ASCII w/o null");
   type_asciiz = new QRadioButton("ASCII w/ null");
   type_file = new QRadioButton("Load from file");   
   
   QGridLayout *gl = new QGridLayout();
   gl->setSpacing(2);
   gl->setContentsMargins(4, 4, 4, 4);
   
   gl->addWidget(type_byte, 0, 0);
   gl->addWidget(type_ascii, 0, 1);
   gl->addWidget(type_word, 1, 0);
   gl->addWidget(type_asciiz, 1, 1);
   gl->addWidget(type_dword, 2, 0);
   gl->addWidget(type_file, 2, 1);
   
   QGroupBox *groupBox = new QGroupBox("Data type");
   groupBox->setLayout(gl);
   
   char buf[32];
   ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)get_screen_ea());
   mem_start = new QLineEdit(buf);
   mem_start->setValidator(&aiv);
   mem_values = new QLineEdit(this);

   address->setBuddy(mem_start);
   values->setBuddy(mem_values);
   
   type_byte->setChecked(true);
   
   QVBoxLayout *vbl = new QVBoxLayout();
   vbl->setSpacing(2);
   vbl->setContentsMargins(4, 4, 4, 4);
   vbl->addWidget(address);
   vbl->addWidget(mem_start);
   vbl->addWidget(new QWidget());
   vbl->addWidget(new QWidget());
   
   QWidget *leftPanel = new QWidget();
   leftPanel->setLayout(vbl);
   
   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addWidget(leftPanel);
   hbl->addWidget(groupBox);
   
   QWidget *topPanel = new QWidget();
   topPanel->setLayout(hbl);
   
   QVBoxLayout *mainLayout = new QVBoxLayout();
   mainLayout->setSpacing(2);
   mainLayout->setContentsMargins(4, 4, 4, 4);
   mainLayout->addWidget(topPanel);
   mainLayout->addWidget(values);
   mainLayout->addWidget(mem_values);
   mainLayout->addWidget(buttonPanel);
   
   setLayout(mainLayout);
      
   connect(set_ok, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(set_cancel, SIGNAL(clicked()), this, SLOT(reject()));
   
   setWindowTitle("Set Memory Values");   
}

void showInformationMessage(const char *title, const char *msg) {
   QMessageBox::information(getWidgetParent(), title, msg);
}

bool getMmapBlockData(unsigned int *base, unsigned int *size) {
   char msg_buf[128];
   MmapDialog mm(getWidgetParent());
   if (mm.exec()) {
      QByteArray _ms = mm.mmap_size->text().toAscii(); 
      char *ms = _ms.data();
      char *endptr;
      *size = strtoul(ms, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid mmap size: %s, cancelling mmap allocation", ms);
         showErrorMessage(msg_buf);
         return false;
      }
      QByteArray _mb = mm.mmap_base->text().toAscii();
      char *mb = _mb.data();
      *base = strtoul(mb, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid mmap base: %s, cancelling mmap allocation", mb);
         showErrorMessage(msg_buf);
         return false;
      }
      return true;
   }
   return false;
}

void showWaitCursor() {
   QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
}

void restoreCursor() {
   QApplication::restoreOverrideCursor();
}

void MmapDialog::do_ok() {
   accept();
}

//open an mmap input dialog.
MmapDialog::MmapDialog(QWidget *parent) : QDialog(parent) {
   setWindowTitle("mmap Memory Block");
   QLabel *textLabel1 = new QLabel("Base address (0 for any)");
   QLabel *textLabel2 = new QLabel("Block size");

//   SendDlgItemMessage(hwndDlg, IDC_MMAP_SIZE, WM_SETFONT, (WPARAM)fixed, FALSE);
   mmap_base = new QLineEdit("0");
   mmap_base->setValidator(&aiv);
   mmap_size = new QLineEdit("0x1000");
   mmap_size->setValidator(&aiv);
   
   textLabel1->setBuddy(mmap_base);
   textLabel2->setBuddy(mmap_size);
   
   QPushButton *okButton = new QPushButton("&OK");
   okButton->setDefault(true);
   
   QPushButton *cancelButton = new QPushButton("&Cancel");
   
   connect(okButton, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
   
   QHBoxLayout *buttonLayout = new QHBoxLayout;
   buttonLayout->setSpacing(2);
   buttonLayout->setContentsMargins(4, 4, 4, 4);
   buttonLayout->addStretch(1);
   buttonLayout->addWidget(okButton);
   buttonLayout->addWidget(cancelButton);
   buttonLayout->addStretch(1);
   
   QGridLayout *mainLayout = new QGridLayout;
   mainLayout->setSpacing(2);
   mainLayout->setContentsMargins(4, 4, 4, 4);
   mainLayout->addWidget(textLabel1, 0, 0);
   mainLayout->addWidget(mmap_base, 1, 0);
   mainLayout->addWidget(textLabel2, 2, 0);
   mainLayout->addWidget(mmap_size, 3, 0);
   mainLayout->addLayout(buttonLayout, 4, 0, 1, 2);
   setLayout(mainLayout);
   
   mmap_base->setFocus();
}

static QString &formatReg(QString &qs, const char *format, unsigned int val) {
   char buf[32];
   ::qsnprintf(buf, sizeof(buf), format, val);
   qs = buf;
   return qs;
}

void SegmentsDialog::do_ok() {
   _cs = strtoul(qcs_reg->text().toAscii().data(), NULL, 0);
   _ds = strtoul(qds_reg->text().toAscii().data(), NULL, 0);
   _es = strtoul(qes_reg->text().toAscii().data(), NULL, 0);
   _fs = strtoul(qfs_reg->text().toAscii().data(), NULL, 0);
   _gs = strtoul(qgs_reg->text().toAscii().data(), NULL, 0);
   _ss = strtoul(qss_reg->text().toAscii().data(), NULL, 0);

   csBase = strtoul(qcs_base->text().toAscii().data(), NULL, 0);
   dsBase = strtoul(qds_base->text().toAscii().data(), NULL, 0);
   esBase = strtoul(qes_base->text().toAscii().data(), NULL, 0);
   fsBase = strtoul(qfs_base->text().toAscii().data(), NULL, 0);
   gsBase = strtoul(qgs_base->text().toAscii().data(), NULL, 0);
   ssBase = strtoul(qss_base->text().toAscii().data(), NULL, 0);

   accept();
}

SegmentsDialog::SegmentsDialog(QWidget *parent) : QDialog(parent) {
   QString v;
   setSizeGripEnabled(false);
   setModal(true);

   qcs_reg = new QLineEdit(formatReg(v, "0x%4.4X", _cs));
   qcs_reg->setValidator(&aiv);
   qgs_reg = new QLineEdit(formatReg(v, "0x%4.4X", _gs));
   qgs_reg->setValidator(&aiv);
   qss_reg = new QLineEdit(formatReg(v, "0x%4.4X", _ss));
   qss_reg->setValidator(&aiv);
   qds_reg = new QLineEdit(formatReg(v, "0x%4.4X", _ds));
   qds_reg->setValidator(&aiv);
   qes_reg = new QLineEdit(formatReg(v, "0x%4.4X", _es));
   qes_reg->setValidator(&aiv);
   qfs_reg = new QLineEdit(formatReg(v, "0x%4.4X", _fs));
   qfs_reg->setValidator(&aiv);
   
   QFormLayout *left = new QFormLayout();
   left->setSpacing(2);
   left->setContentsMargins(4, 4, 4, 4);
   //add label/edit pairs
   left->addRow("CS", qcs_reg);
   left->addRow("SS", qss_reg);
   left->addRow("DS", qds_reg);
   left->addRow("ES", qes_reg);
   left->addRow("FS", qfs_reg);
   left->addRow("GS", qgs_reg);

   QWidget *leftPanel = new QWidget();
   leftPanel->setLayout(left);

   qds_base = new QLineEdit(formatReg(v, "0x%08X", dsBase));
   qds_base->setValidator(&aiv);
   qcs_base = new QLineEdit(formatReg(v, "0x%08X", csBase));
   qcs_base->setValidator(&aiv);
   qgs_base = new QLineEdit(formatReg(v, "0x%08X", gsBase));
   qgs_base->setValidator(&aiv);
   qfs_base = new QLineEdit(formatReg(v, "0x%08X", fsBase));
   qfs_base->setValidator(&aiv);
   qss_base = new QLineEdit(formatReg(v, "0x%08X", ssBase));
   qss_base->setValidator(&aiv);
   qes_base = new QLineEdit(formatReg(v, "0x%08X", esBase));
   qes_base->setValidator(&aiv);
   
   QFormLayout *right = new QFormLayout();
   right->setSpacing(2);
   right->setContentsMargins(4, 4, 4, 4);
   right->addRow("CS base", qcs_base);
   right->addRow("SS base", qss_base);
   right->addRow("DS base", qds_base);
   right->addRow("ES base", qes_base);
   right->addRow("FS base", qfs_base);
   right->addRow("GS base", qgs_base);

   QWidget *rightPanel = new QWidget();
   rightPanel->setLayout(right);

   QHBoxLayout *topBox = new QHBoxLayout();  //for registers
   topBox->setSpacing(2);
   topBox->setContentsMargins(4, 4, 4, 4);
   topBox->addWidget(leftPanel);
   topBox->addWidget(rightPanel);

   QWidget *topPanel = new QWidget();
   topPanel->setLayout(topBox);

   QPushButton *seg_ok = new QPushButton("&OK");
   seg_ok->setAutoDefault(true);
   seg_ok->setDefault(true);
   
   QPushButton *seg_cancel = new QPushButton("&Cancel");
   seg_cancel->setAutoDefault(true);
   
   QHBoxLayout *bl = new QHBoxLayout(); //for buttons
   bl->setSpacing(2);
   bl->setContentsMargins(4, 4, 4, 4);
   //add buttons
   bl->addStretch(1);
   bl->addWidget(seg_ok);
   bl->addWidget(seg_cancel);
   bl->addStretch(1);
   
   QWidget *buttonBox = new QWidget();
   buttonBox->setLayout(bl);

   QVBoxLayout *main = new QVBoxLayout();  //for registers
   main->setSpacing(2);
   main->setContentsMargins(4, 4, 4, 4);
   main->addWidget(topPanel);
   main->addWidget(buttonBox);

   setLayout(main);
   
   connect(seg_ok, SIGNAL(clicked()), this, SLOT(do_ok()));
   connect(seg_cancel, SIGNAL(clicked()), this, SLOT(reject()));
   
   setWindowTitle("Segment Configuration");
}

void changeReg(int reg, const QString &val) {
   setRegisterValue(reg, strtoul(val.toAscii().data(), NULL, 0));
}

void X86Dialog::changeEax() {
   changeReg(EAX, QEAX->text());
}

void X86Dialog::changeEbx() {
   changeReg(EBX, QEBX->text());
}

void X86Dialog::changeEcx() {
   changeReg(ECX, QECX->text());
}

void X86Dialog::changeEdx() {
   changeReg(EDX, QEDX->text());
}

void X86Dialog::changeEdi() {
   changeReg(EDI, QEDI->text());
}

void X86Dialog::changeEsi() {
   changeReg(ESI, QESI->text());
}

void X86Dialog::changeEbp() {
   changeReg(EBP, QEBP->text());
}

void X86Dialog::changeEsp() {
   changeReg(ESP, QESP->text());
}

void X86Dialog::changeEip() {
   changeReg(EIP, QEIP->text());
}

void X86Dialog::changeEflags() {
   changeReg(EFLAGS, QEFLAGS->text());
}

void X86Dialog::settings() {
   MemConfigDialog mc(this);
   mc.exec();
}

//ask user for an address range and dump that address range
//to a user named file;
void X86Dialog::dumpRange() {
   ::dumpRange();
}

//ask user for an address range and dump that address range
//to a user named file;
void X86Dialog::dumpEmbededPE() {
   ::dumpEmbededPE();
}

void X86Dialog::grabStackBlock() {
   ::grabStackBlock();
}

void X86Dialog::grabHeapBlock() {
   ::grabHeapBlock();
}

void X86Dialog::buildMainArgs() {
   ::buildMainArgs();
}

void X86Dialog::buildWinMainArgs() {
   ::buildWinMainArgs();
}

void X86Dialog::buildDllMainArgs() {
   ::buildDllMainArgs();
}

void X86Dialog::grabMmapBlock() {
   ::grabMmapBlock();
}

void X86Dialog::reset() {
   doReset();
}

void X86Dialog::trackExec() {
   if (getTracking()) {
      emulateTrack_fetched_bytesAction->setChecked(false);
   }
   else {
      emulateTrack_fetched_bytesAction->setChecked(true);
   }
   setTracking(!getTracking());
}

void X86Dialog::traceExec() {
   if (getTracing()) {
      emulateTrace_executionAction->setChecked(false);
      closeTrace();
   }
   else {
      emulateTrace_executionAction->setChecked(true);
      openTraceFile();
   }
   setTracing(!getTracing()); 
}

void X86Dialog::logLibraryCalls() {
   emulateLogLibraryAction->setChecked(!logLibrary());
   setLogLibrary(!logLibrary()); 
}

void X86Dialog::breakOnExceptions() {
   emulateBreakOnExceptionsAction->setChecked(!::breakOnExceptions);
   setBreakOnExceptions(!::breakOnExceptions); 
}

void X86Dialog::breakOnSyscall() {
   emulateBreakSyscallAction->setChecked(!::breakOnSyscall());
   setBreakOnSyscall(!::breakOnSyscall()); 
}

void X86Dialog::logSystemCalls() {
   emulateLogSyscallsAction->setChecked(!logSyscalls());
   setLogSyscalls(!logSyscalls()); 
}

void X86Dialog::setImportAddressSavePoint() {
   tagImportAddressSavePoint();
}

void X86Dialog::setBreak() {
   setBreakpoint();
}

void X86Dialog::clearBreak() {
   clearBreakpoint();
}

void X86Dialog::memoryException() {
   generateMemoryException();
}

void X86Dialog::exportLookup() {
   doExportLookup();
}

void X86Dialog::switchThreads() {
   ThreadsDialog t(x86Dlg);
   t.exec();
}

void X86Dialog::hideEmu() {
   x86Dlg->hide();
}

void X86Dialog::heapList() {
   dumpHeap();
}

void X86Dialog::step() {
   stepOne();
}

void X86Dialog::skip() {
   ::skip();
}

void X86Dialog::run() {
   BREAK->setEnabled(true);
   ::run();
   BREAK->setEnabled(false);
}

void X86Dialog::doBreak() {
   shouldBreak = 1;
}

void X86Dialog::runCursor() {
   BREAK->setEnabled(true);
   ::runToCursor();
   BREAK->setEnabled(false);
}

void X86Dialog::jumpCursor() {
   ::jumpToCursor();
}

//ask the user for space separated data and push it onto the
//stack in right to left order as a C function would
void X86Dialog::pushData() {
   ::pushData();
}

void X86Dialog::setMemory() {
   SetMemoryDialog mem(this);
   mem.exec();
}

void X86Dialog::segments() {
   SegmentsDialog segs(this);
   segs.exec();
}

void X86Dialog::loadLibrary() {
   ::loadLibrary();
}

#define X86_WINDOW_FLAGS Qt::CustomizeWindowHint | \
                         Qt::WindowTitleHint | \
                         Qt::WindowMinimizeButtonHint | \
                         Qt::WindowCloseButtonHint | \
                         Qt::Tool
X86Dialog::X86Dialog(QWidget *parent) : QMainWindow(parent, X86_WINDOW_FLAGS) {   
   QAction *fileDumpAction = new QAction("Dump", this);
   QAction *fileDump_embedded_PEAction = new QAction("Dump embedded PE", this);
   QAction *fileCloseAction = new QAction("Close", this);   
   QAction *editStackAction = new QAction("Stack", this);
   QAction *editSegment_registersAction = new QAction("Segment registers...", this);
   QAction *viewEnumerate_heapAction = new QAction("Enumerate heap", this);
   QAction *viewResetAction = new QAction("Reset", this);
   QAction *emulateSettingsAction = new QAction("Settings", this);
   QAction *emulateSet_breakpointAction = new QAction("Set breakpoint...", this);
   QAction *emulateRemove_breakpointAction = new QAction("Remove breakpoint...", this);
   QAction *emulateSwitch_threadAction = new QAction("Switch thread...", this);
   QAction *emulateWindowsAuto_hookAction = new QAction("Auto hook", this);
   QAction *emulateWindowsLoadLibraryAction = new QAction("Load entire library file...", this);
   QAction *emulateWindowsSet_import_addr_save_pointAction = new QAction("Set import addr save point", this);
   QAction *emulateWindowsExport_lookupAction = new QAction("Export lookup...", this);

   emulateTrack_fetched_bytesAction = new QAction("Track fetched bytes", this);
   emulateTrack_fetched_bytesAction->setCheckable(true);

   emulateTrace_executionAction = new QAction("Trace execution", this);
   emulateTrace_executionAction->setCheckable(true);

   emulateLogLibraryAction = new QAction("Log library calls", this);
   emulateLogLibraryAction->setCheckable(true);
   emulateLogLibraryAction->setChecked(doLogLib);

   emulateBreakOnExceptionsAction = new QAction("Break on exceptions", this);
   emulateBreakOnExceptionsAction->setCheckable(true);
   emulateBreakOnExceptionsAction->setChecked(::breakOnExceptions);

   emulateBreakSyscallAction = new QAction("Break on system call", this);
   emulateBreakSyscallAction->setCheckable(true);
   emulateBreakSyscallAction->setChecked(doBreakOnSyscall);

   emulateLogSyscallsAction = new QAction("Log system calls", this);
   emulateLogSyscallsAction->setCheckable(true);
   emulateLogSyscallsAction->setChecked(doLogSyscalls);

   QAction *emulateWindowsThrow_exceptionMemory_accessAction = new QAction("Memory access", this);
   QAction *emulateWindowsThrow_exceptionBreakpointAction = new QAction("Breakpoint", this);
   QAction *emulateWindowsThrow_exceptionDivide_by_zeroAction = new QAction("Divide by zero", this);
   QAction *emulateWindowsThrow_exceptionDebugAction = new QAction("Debug", this);
   QAction *functionsAllocate_heap_blockAction = new QAction("Allocate heap block...", this);
   QAction *functionsAllocate_stack_blockAction = new QAction("Allocate stack block...", this);
   QAction *functionsAllocate_mmap_blockAction = new QAction("Allocate mmap block...", this);
   QAction *functionsPushMain_argsAction = new QAction("Push main args", this);
   QAction *functionsPushWinMain_argsAction = new QAction("Push WinMain args", this);
   QAction *functionsPushDllMain_argsAction = new QAction("Push DllMain args", this);

   QEAX = new QLineEdit();
   QEAX->setValidator(&aiv);
   QFont font1;
   font1.setFamily(QString::fromUtf8("Courier"));
   QEAX->setFont(font1);
   QEBX = new QLineEdit();
   QEBX->setValidator(&aiv);
   QEBX->setFont(font1);
   QECX = new QLineEdit();
   QECX->setValidator(&aiv);
   QECX->setFont(font1);
   QEDX = new QLineEdit();
   QEDX->setValidator(&aiv);
   QEDX->setFont(font1);
   QEFLAGS = new QLineEdit();
   QEFLAGS->setValidator(&aiv);
   QEFLAGS->setFont(font1);
   QEBP = new QLineEdit();
   QEBP->setValidator(&aiv);
   QEBP->setFont(font1);
   QESP = new QLineEdit();
   QESP->setValidator(&aiv);
   QESP->setFont(font1);
   QESI = new QLineEdit();
   QESI->setValidator(&aiv);
   QESI->setFont(font1);
   QEDI = new QLineEdit();
   QEDI->setValidator(&aiv);
   QEDI->setFont(font1);
   QEIP = new QLineEdit();
   QEIP->setValidator(&aiv);
   QEIP->setFont(font1);

   QFormLayout *left = new QFormLayout();
   left->setSpacing(2);
   left->setContentsMargins(4, 4, 4, 4);
   //add label/edit pairs
   left->addRow("EAX", QEAX);
   left->addRow("EBX", QEBX);
   left->addRow("ECX", QECX);
   left->addRow("EDX", QEDX);
   left->addRow("EFLAGS", QEFLAGS);

   QWidget *leftPanel = new QWidget();
   leftPanel->setLayout(left);

   QFormLayout *right = new QFormLayout();
   right->setSpacing(2);
   right->setContentsMargins(4, 4, 4, 4);
   right->addRow("EBP", QEBP);
   right->addRow("ESP", QESP);
   right->addRow("ESI", QESI);
   right->addRow("EDI", QEDI);
   right->addRow("EIP", QEIP);

   QWidget *rightPanel = new QWidget();
   rightPanel->setLayout(right);

   QHBoxLayout *regBox = new QHBoxLayout();  //for registers
   regBox->setSpacing(2);
   regBox->setContentsMargins(4, 4, 4, 4);
   regBox->addWidget(leftPanel);
   regBox->addWidget(rightPanel);

   QGroupBox *REGISTERS = new QGroupBox("Registers");
   REGISTERS->setLayout(regBox);

   QPushButton *SET_MEMORY = new QPushButton("Set Memory");
   QPushButton *RUN = new QPushButton("Run");
   BREAK = new QPushButton("Break");
   QPushButton *SKIP = new QPushButton("Skip");
   QPushButton *STEP = new QPushButton("Step");
   QPushButton *RUN_TO_CURSOR = new QPushButton("Run to cursor");
   QPushButton *PUSH_DATA = new QPushButton("Push data");
   QPushButton *SEGMENTS = new QPushButton("Segments");
   QPushButton *JUMP_TO_CURSOR = new QPushButton("Jump to cursor");
   
   QGridLayout *gl = new QGridLayout(); //for buttons
   gl->setSpacing(2);
   gl->setContentsMargins(4, 4, 4, 4);
   //add buttons
   gl->addWidget(STEP, 0, 0);
   gl->addWidget(RUN_TO_CURSOR, 0, 1);
   gl->addWidget(SKIP, 1, 0);
   gl->addWidget(JUMP_TO_CURSOR, 1, 1);
   gl->addWidget(RUN, 2, 0);
   gl->addWidget(BREAK, 2, 1);
   gl->addWidget(SEGMENTS, 3, 1);
   gl->addWidget(SET_MEMORY, 4, 0);
   gl->addWidget(PUSH_DATA, 4, 1);
   
   QWidget *buttons = new QWidget();
   buttons->setLayout(gl);

   QHBoxLayout *hbl = new QHBoxLayout();
   hbl->setSpacing(2);
   hbl->setContentsMargins(4, 4, 4, 4);
   hbl->addWidget(REGISTERS);
   hbl->addWidget(buttons);

   QWidget *central = new QWidget(this);
   central->setLayout(hbl);
   
   setCentralWidget(central);

   QToolBar *toolBar = new QToolBar();
   toolBar->setMovable(false);

   QMenu *File = new QMenu("File", this);
   QMenu *Edit = new QMenu("Edit", this);
   QMenu *View = new QMenu("View", this);
   QMenu *Emulate = new QMenu("Emulate", this);
   QMenu *popupMenu_13 = new QMenu("Windows", this);
   QMenu *popupMenu_16 = new QMenu("Throw exception", popupMenu_13);
   QMenu *Functions = new QMenu("Functions", this);
   QMenu *popupMenu_18 = new QMenu("Push", Functions);

   addToolBar(toolBar);
      
   setTabOrder(QEAX, QEBX);
   setTabOrder(QEBX, QECX);
   setTabOrder(QECX, QEDX);
   setTabOrder(QEDX, QEFLAGS);
   setTabOrder(QEFLAGS, QEBP);
   setTabOrder(QEBP, QESP);
   setTabOrder(QESP, QESI);
   setTabOrder(QESI, QEDI);
   setTabOrder(QEDI, QEIP);
   setTabOrder(QEIP, STEP);
   setTabOrder(STEP, RUN_TO_CURSOR);
   setTabOrder(RUN_TO_CURSOR, SKIP);
   setTabOrder(SKIP, JUMP_TO_CURSOR);
   setTabOrder(JUMP_TO_CURSOR, RUN);
   setTabOrder(RUN, SEGMENTS);
   setTabOrder(SEGMENTS, SET_MEMORY);
   setTabOrder(SET_MEMORY, PUSH_DATA);

   toolBar->addAction(File->menuAction());
   toolBar->addAction(Edit->menuAction());
   toolBar->addAction(View->menuAction());
   toolBar->addAction(Emulate->menuAction());
   toolBar->addAction(Functions->menuAction());

   File->addAction(fileDumpAction);
   File->addAction(fileDump_embedded_PEAction);
   File->addSeparator();
   File->addAction(fileCloseAction);

   Edit->addAction(editStackAction);
   Edit->addAction(editSegment_registersAction);
   View->addAction(viewEnumerate_heapAction);
   View->addAction(viewResetAction);

   Emulate->addAction(emulateSettingsAction);
   Emulate->addAction(emulateSet_breakpointAction);
   Emulate->addAction(emulateRemove_breakpointAction);
   Emulate->addAction(emulateSwitch_threadAction);
   Emulate->addAction(popupMenu_13->menuAction());
   Emulate->addSeparator();
   Emulate->addAction(emulateTrack_fetched_bytesAction);
   Emulate->addAction(emulateTrace_executionAction);
   Emulate->addAction(emulateLogLibraryAction);
   Emulate->addAction(emulateBreakOnExceptionsAction);
   Emulate->addAction(emulateBreakSyscallAction);
   Emulate->addAction(emulateLogSyscallsAction);

   popupMenu_13->addAction(emulateWindowsAuto_hookAction);
   popupMenu_13->addAction(emulateWindowsLoadLibraryAction);
   popupMenu_13->addAction(emulateWindowsSet_import_addr_save_pointAction);
   popupMenu_13->addAction(popupMenu_16->menuAction());
   popupMenu_13->addAction(emulateWindowsExport_lookupAction);

   popupMenu_16->addAction(emulateWindowsThrow_exceptionMemory_accessAction);
   popupMenu_16->addAction(emulateWindowsThrow_exceptionBreakpointAction);
   popupMenu_16->addAction(emulateWindowsThrow_exceptionDivide_by_zeroAction);
   popupMenu_16->addAction(emulateWindowsThrow_exceptionDebugAction);

   Functions->addAction(functionsAllocate_heap_blockAction);
   Functions->addAction(functionsAllocate_stack_blockAction);
   Functions->addAction(functionsAllocate_mmap_blockAction);
   Functions->addAction(popupMenu_18->menuAction());

   popupMenu_18->addAction(functionsPushMain_argsAction);
   popupMenu_18->addAction(functionsPushWinMain_argsAction);
   popupMenu_18->addAction(functionsPushDllMain_argsAction);
   
   connect(STEP, SIGNAL(clicked()), this, SLOT(step()));
   connect(SKIP, SIGNAL(clicked()), this, SLOT(skip()));
   connect(RUN, SIGNAL(clicked()), this, SLOT(run()));
   connect(BREAK, SIGNAL(clicked()), this, SLOT(doBreak()));
   connect(RUN_TO_CURSOR, SIGNAL(clicked()), this, SLOT(runCursor()));
   connect(JUMP_TO_CURSOR, SIGNAL(clicked()), this, SLOT(jumpCursor()));
   connect(SET_MEMORY, SIGNAL(clicked()), this, SLOT(setMemory()));
   connect(SEGMENTS, SIGNAL(clicked()), this, SLOT(segments()));
   connect(PUSH_DATA, SIGNAL(clicked()), this, SLOT(pushData()));
   connect(QEAX, SIGNAL(editingFinished()), this, SLOT(changeEax()));
   connect(QEBX, SIGNAL(editingFinished()), this, SLOT(changeEbx()));
   connect(QECX, SIGNAL(editingFinished()), this, SLOT(changeEcx()));
   connect(QEDX, SIGNAL(editingFinished()), this, SLOT(changeEdx()));
   connect(QEFLAGS, SIGNAL(editingFinished()), this, SLOT(changeEflags()));
   connect(QEIP, SIGNAL(editingFinished()), this, SLOT(changeEip()));
   connect(QEDI, SIGNAL(editingFinished()), this, SLOT(changeEdi()));
   connect(QESI, SIGNAL(editingFinished()), this, SLOT(changeEsi()));
   connect(QESP, SIGNAL(editingFinished()), this, SLOT(changeEsp()));
   connect(QEBP, SIGNAL(editingFinished()), this, SLOT(changeEbp()));

   connect(fileDumpAction, SIGNAL(triggered()), this, SLOT(dumpRange()));
   connect(fileDump_embedded_PEAction, SIGNAL(triggered()), this, SLOT(dumpEmbededPE()));
   connect(fileCloseAction, SIGNAL(triggered()), this, SLOT(hideEmu()));
   connect(editSegment_registersAction, SIGNAL(triggered()), this, SLOT(segments()));
   connect(emulateSet_breakpointAction, SIGNAL(triggered()), this, SLOT(setBreak()));
   connect(emulateRemove_breakpointAction, SIGNAL(triggered()), this, SLOT(clearBreak()));
   connect(emulateSettingsAction, SIGNAL(triggered()), this, SLOT(settings()));
   connect(emulateSwitch_threadAction, SIGNAL(triggered()), this, SLOT(switchThreads()));
   connect(emulateWindowsLoadLibraryAction, SIGNAL(triggered()), this, SLOT(loadLibrary()));
   connect(emulateWindowsExport_lookupAction, SIGNAL(triggered()), this, SLOT(exportLookup()));
   connect(emulateWindowsSet_import_addr_save_pointAction, SIGNAL(triggered()), this, SLOT(setImportAddressSavePoint()));
   connect(emulateWindowsThrow_exceptionMemory_accessAction, SIGNAL(triggered()), this, SLOT(memoryException()));
   connect(functionsAllocate_stack_blockAction, SIGNAL(triggered()), this, SLOT(grabStackBlock()));
   connect(functionsAllocate_heap_blockAction, SIGNAL(triggered()), this, SLOT(grabHeapBlock()));
   connect(functionsAllocate_mmap_blockAction, SIGNAL(triggered()), this, SLOT(grabMmapBlock()));
   connect(functionsPushMain_argsAction, SIGNAL(triggered()), this, SLOT(buildMainArgs()));
   connect(functionsPushWinMain_argsAction, SIGNAL(triggered()), this, SLOT(buildWinMainArgs()));
   connect(functionsPushDllMain_argsAction, SIGNAL(triggered()), this, SLOT(buildDllMainArgs()));
   connect(viewEnumerate_heapAction, SIGNAL(triggered()), this, SLOT(heapList()));
   connect(viewResetAction, SIGNAL(triggered()), this, SLOT(reset()));
   connect(emulateTrack_fetched_bytesAction, SIGNAL(triggered()), this, SLOT(trackExec()));
   connect(emulateTrace_executionAction, SIGNAL(triggered()), this, SLOT(traceExec()));
   connect(emulateLogLibraryAction, SIGNAL(triggered()), this, SLOT(logLibraryCalls()));
   connect(emulateBreakOnExceptionsAction, SIGNAL(triggered()), this, SLOT(breakOnExceptions()));
   connect(emulateBreakSyscallAction, SIGNAL(triggered()), this, SLOT(breakOnSyscall()));
   connect(emulateLogSyscallsAction, SIGNAL(triggered()), this, SLOT(logSystemCalls()));

   setWindowTitle("x86 Emulator");
}

bool createEmulatorWindow() {
   if (x86Dlg == NULL) {
      x86Dlg = new X86Dialog(getWidgetParent());
      setTitle();
      syncDisplay();
   }
   return true;
}

void destroyEmulatorWindow() {
   if (x86Dlg) {
      x86Dlg->close();
      delete x86Dlg;
      x86Dlg = NULL; 
   }
}

void displayEmulatorWindow() {
   if (x86Dlg == NULL) {
      createEmulatorWindow();
   }
   x86Dlg->show();
}
