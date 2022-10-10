/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2003-2022 Chris Eagle

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

#include <windows.h>
#include <winnt.h>
#include <wincrypt.h>

#ifdef PACKED
#undef PACKED
#endif

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

#include "x86defs.h"
#include "x86emu_ui.h"
#include "resource.h"
#include "cpu.h"
#include "emufuncs.h"
#include "emuthreads.h"

HWND mainWindow;
HFONT fixed;
HWND x86Dlg;
HCURSOR waitCursor;
HMODULE hModule;

//Values used by the mmap dialog box
static char mmap_base[80];
static char mmap_size[80];

//Values used by the input dialog box
static char value[80]; //value entered by the user
static char title[80]; //dynamic title for the input dialog
static char prompt[80]; //dynamic prompt for the input dialog
static char initial[80]; //dynamic initial value for the input dialog

//This is the original window procedure for the register edit controls
//required in order to subclass the controls to handle double clicks
static LONG oldProc;
static LONG oldSegProc;

//text names for each of the register edit controls
const char *names[] = {"EAX", "EBX", "ECX", "EDX", "EBP",
                       "ESP", "ESI", "EDI", "EIP", "EFLAGS"};

//window handles for each of the register edit controls
static HWND editBoxes[10];

//callback for events in the emulator window
BOOL CALLBACK DlgProc(HWND, UINT, WPARAM, LPARAM);

//callback for mmap dialog events
BOOL CALLBACK MmapDlgProc(HWND, UINT, WPARAM, LPARAM);

//callback for input dialog events
BOOL CALLBACK InputDlgProc(HWND, UINT, WPARAM, LPARAM);

//subclass procedure for the register edit controls
LRESULT EditSubclassProc(HWND, UINT, WPARAM, LPARAM);

extern til_t *ti;

void cacheMainWindowHandle() {
   if (mainWindow == NULL) {
      mainWindow = (HWND)callui(ui_get_hwnd).vptr;
   }
}

/*
 * Set the title of the emulator window
 */
void setEmulatorTitle(const char *title) {
   SendMessage(x86Dlg, WM_SETTEXT, 0, (LPARAM)title);
}

//convert a register number into a control ID for the register's display
int regToControl(unsigned int reg) {
   //offsets from control ID (resource.h) to register id (x86defs.h) set array index
   static int registerMap[10] = {IDC_EAX, IDC_ECX, IDC_EDX, IDC_EBX, IDC_ESP,
                                 IDC_EBP, IDC_ESI, IDC_EDI, IDC_EIP, IDC_EFLAGS};

   return reg <= MAX_REG ? registerMap[reg] : 0;
}

//convert a control ID to a pointer to the corresponding register
int controlToReg(int controlID) {
   //offsets from control ID to register set array index
   static int registerMap[10] = {0, 2, -1, -1, 1, -1, 0, 0, 0, 0};

   controlID -= IDC_EAX;
   if (controlID >= MIN_REG && controlID <= MAX_REG) {
      return controlID + registerMap[controlID];
   }
   return -1;
}

unsigned int *controlToRegPtr(int control) {
   int reg = controlToReg(control);
   return getRegisterPointer(reg);
}

//update the specified register display with the specified
//value.  useful to update register contents based on user
//input
void updateRegisterDisplay(int r) {
   static bool registersSet[MAX_REG + 1];
   static unsigned int current[MAX_REG + 1];
   char buf[16];
   unsigned int rval = getRegisterValue(r);
   ::qsnprintf(buf, sizeof(buf), "0x%08X", rval);
   if (registersSet[r]) {
      if (rval != current[r]) { //set text color to red
         current[r] = rval;
//         SendDlgItemMessage(x86Dlg, regToControl(r), 
      }
      else { //set text color to black
//         SendDlgItemMessage(x86Dlg, regToControl(r), 
      }
   }
   else {
      registersSet[r] = true;
      current[r] = rval;
   }
   SetDlgItemText(x86Dlg, regToControl(r), buf);
}

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

//get an int value from edit box string
//assumes value is a valid hex string
unsigned int getEditBoxInt(HWND dlg, int dlgItem) {
   char value[80];
   unsigned int newVal = 0;
   GetDlgItemText(dlg, dlgItem, value, 80);
   if (strlen(value) != 0) {
//      sscanf(value, "%X", &newVal);
      newVal = strtoul(value, NULL, 0);
   }
   return newVal;
}

//display a single line input box with the given title, prompt
//and initial data value.  If the user does not cancel, their
//data is placed into the global variable "value"
char *inputBox(const char *boxTitle, const char *msg, const char *init) {
   ::qstrncpy(title, boxTitle, 80);
   title[79] = 0;
   ::qstrncpy(prompt, msg, 80);
   prompt[79] = 0;
   ::qstrncpy(initial, init, 80);
   initial[79] = 0;
   int result = DialogBox(hModule, MAKEINTRESOURCE(IDD_INPUTDIALOG),
                          x86Dlg, InputDlgProc);
   return result == 2 ? value : NULL;
}

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

char *getDirectoryName(const char *title, char *dirName, int nameSize) {
   OPENFILENAME ofn;
   if (dirName == NULL || nameSize == 0) {
      return NULL;
   }
   memset(&ofn, 0, sizeof(ofn));

   // Initialize OPENFILENAME
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = x86Dlg;
   ofn.lpstrFile = dirName;
   //
   // Set lpstrFile[0] to '\0' so that GetOpenFileName does not
   // use the contents of szFile to initialize itself.
   //
   *dirName = '\0';
   ofn.nMaxFile = nameSize;
   ofn.lpstrFilter = NULL;
   ofn.nFilterIndex = 1;
   ofn.lpstrFileTitle = NULL;
   ofn.nMaxFileTitle = 0;
   ofn.lpstrInitialDir = NULL;
   ofn.lpstrTitle = title;
   ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
   if (GetOpenFileName(&ofn)) {
      return dirName;
   }
   return NULL;
}

char *getSaveFileName(const char *title, char *fileName, int nameSize, const char *filter) {
   OPENFILENAME ofn;
   if (fileName == NULL || nameSize == 0) {
      return NULL;
   }
   memset(&ofn, 0, sizeof(ofn));

   // Initialize OPENFILENAME
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = x86Dlg;
   ofn.lpstrFile = fileName;
   //
   // Set lpstrFile[0] to '\0' so that GetOpenFileName does not
   // use the contents of szFile to initialize itself.
   //
   *fileName = '\0';
   ofn.nMaxFile = nameSize;
   ofn.lpstrFilter = filter;
   ofn.nFilterIndex = 1;
   ofn.lpstrFileTitle = NULL;
   ofn.nMaxFileTitle = 0;
   ofn.lpstrInitialDir = NULL;
   ofn.lpstrTitle = title;
   ofn.Flags = OFN_OVERWRITEPROMPT;
   if (GetSaveFileName(&ofn)) {
      return fileName;
   }
   return NULL;
}

void showErrorMessage(const char *msg) {
   MessageBox(x86Dlg, msg, "Error", MB_OK | MB_ICONWARNING);
}

static const char *unemulatedName;
static unsigned int unemulatedAddr;

struct UnemulatedCbStruct {
   HWND dlg;
   HDC hdc;
   int maxLength;
};

void argCallback(const char *func, const char *arg, int idx, void *user) {
   UnemulatedCbStruct *cbs = (UnemulatedCbStruct*)user;
   SendDlgItemMessage(cbs->dlg, IDC_PARM_LIST, LB_ADDSTRING, (WPARAM)0, (LPARAM)arg);
   SIZE sz;
   GetTextExtentPoint32(cbs->hdc, arg, strlen(arg), &sz);
   if (sz.cx > cbs->maxLength) {
      cbs->maxLength = sz.cx;
   }
}

BOOL CALLBACK UnemulatedDlgProc(HWND hwndDlg, UINT message,
                                WPARAM wParam, LPARAM lParam) {
   char buf[256];
   FunctionInfo *f;
   switch (message) {
      case WM_INITDIALOG: {
         if (unemulatedName) {
            ::qsnprintf(buf, sizeof(buf), "Call to: %s", unemulatedName);
         }
         else {
            ::qsnprintf(buf, sizeof(buf), "Call to: Location 0x%08.8x", unemulatedAddr);
         }

         SendMessage(hwndDlg, WM_SETTEXT, (WPARAM)0, (LPARAM)buf);

         SendDlgItemMessage(hwndDlg, IDC_PARM_LIST, WM_SETFONT, (WPARAM)fixed, FALSE);
         SendDlgItemMessage(hwndDlg, IDC_RETURN_VALUE, WM_SETFONT, (WPARAM)fixed, FALSE);
         SendDlgItemMessage(hwndDlg, IDC_CLEAR_STACK, WM_SETFONT, (WPARAM)fixed, FALSE);

         int len = 8;
         f = getFunctionInfo(unemulatedName);
         if (f) {
            len = f->stackItems;
            ::qsnprintf(buf, sizeof(buf), "0x%8.8x", f->result);
            SetDlgItemText(hwndDlg, IDC_RETURN_VALUE, buf);
            SetDlgItemInt(hwndDlg, IDC_CLEAR_STACK, f->stackItems, FALSE);
            CheckRadioButton(hwndDlg, IDC_CALL_CDECL, IDC_CALL_STDCALL,
               (f->callingConvention == CALL_CDECL) ? IDC_CALL_CDECL : IDC_CALL_STDCALL);
            char *ret_type = getFunctionReturnType(f);
            if (ret_type) {
               ::qsnprintf(buf, sizeof(buf), "Return type: %s", ret_type);
               SendDlgItemMessage(hwndDlg, IDC_RETURN_LABEL, WM_SETTEXT, (WPARAM)0, (LPARAM)buf);
               free(ret_type);
            }
         }
/*
         else {
            CheckRadioButton(hwndDlg, IDC_CALL_CDECL, IDC_CALL_STDCALL, IDC_CALL_CDECL);
         }
*/
         UnemulatedCbStruct cbs;
         cbs.dlg = hwndDlg;
         cbs.maxLength = 0;
         cbs.hdc = CreateDC("DISPLAY", NULL, NULL, NULL);
         SelectObject(cbs.hdc, fixed);
         generateArgList(unemulatedName, argCallback, &cbs);
         SendDlgItemMessage(hwndDlg, IDC_PARM_LIST, LB_SETHORIZONTALEXTENT, (WPARAM)cbs.maxLength, (LPARAM)0);
         DeleteDC(cbs.hdc);

         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDOK: {//OK Button
               unsigned int retval = 0;
               GetDlgItemText(hwndDlg, IDC_RETURN_VALUE, buf, sizeof(buf));
               if (strlen(buf)) {
                  retval = strtoul(buf, NULL, 0);
                  eax = retval;
               }

               GetDlgItemText(hwndDlg, IDC_CLEAR_STACK, buf, sizeof(buf));
               unsigned int stackfree = strtoul(buf, NULL, 0);
               unsigned int callType = 0xFFFFFFFF;
               if (IsDlgButtonChecked(hwndDlg, IDC_CALL_CDECL) == BST_CHECKED) {
                  callType = CALL_CDECL;
               }
               else if (IsDlgButtonChecked(hwndDlg, IDC_CALL_STDCALL) == BST_CHECKED) {
                  callType = CALL_STDCALL;
               }
               else {
                  MessageBox(hwndDlg, "Please select a calling convention.",
                             "Error", MB_OK | MB_ICONWARNING);
               }
               if (callType != 0xFFFFFFFF) {
                  addFunctionInfo(unemulatedName, retval, stackfree, callType);
                  if (callType == CALL_STDCALL) {
                     esp += stackfree * 4;
                  }
                  EndDialog(hwndDlg, 0);
               }
               return true;
            }
         }
   }
   return FALSE;
}

/*
 * This function is used for all unemulated API functions
 */
void handleUnemulatedFunction(unsigned int addr, const char *name) {
   unemulatedName = name;
   unemulatedAddr = addr;
   DialogBox(hModule, MAKEINTRESOURCE(IDD_UNEMULATED), x86Dlg, UnemulatedDlgProc);
}

/*
 * Ask the user which thread they would like to switch to
 * and make the necessary changes to the cpu state.
 */
BOOL CALLBACK SwitchThreadDlgProc(HWND hwndDlg, UINT message,
                                  WPARAM wParam, LPARAM lParam) {
   char buf[64];
   switch (message) {
      case WM_INITDIALOG: {
         SendDlgItemMessage(hwndDlg, IDC_THREAD_LIST, WM_SETFONT, (WPARAM)fixed, FALSE);

         for (ThreadNode *tn = threadList; tn; tn = tn->next) {
            ::qsnprintf(buf, sizeof(buf), "Thread 0x%x%s", tn->handle, tn->next ? "" : " (main)");
            SendDlgItemMessage(hwndDlg, IDC_THREAD_LIST, LB_ADDSTRING, (WPARAM)0, (LPARAM)buf);
         }
         return TRUE;
      }
      case WM_COMMAND: {
         int selected, idx = 0;
         switch (LOWORD(wParam)) {
            case IDOK: //Switch Button
               selected = SendDlgItemMessage(hwndDlg, IDC_THREAD_LIST, LB_GETCURSEL, 0, 0);
               if (selected != LB_ERR) {
                  switchThread(selected);
               }
               EndDialog(hwndDlg, 0);
               return TRUE;
            case ID_DESTROY: //Destroy Button
               selected = SendDlgItemMessage(hwndDlg, IDC_THREAD_LIST, LB_GETCURSEL, 0, 0);
               if (selected != LB_ERR) {
                  destroyThread(selected);
               }
               EndDialog(hwndDlg, 0);
               return TRUE;
            case IDCANCEL: //CANCEL Button
               EndDialog(hwndDlg, 0);
               return TRUE;
         }
      }
   }
   return FALSE;
}

BOOL CALLBACK SegmentDlgProc(HWND hwndDlg, UINT message,
                             WPARAM wParam, LPARAM lParam) {
   char buf[16];
   int i;
   switch (message) {
      case WM_INITDIALOG: {
         for (i = IDC_CS_REG; i <= IDC_GS_BASE; i++) {
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
            if (i < IDC_CS_BASE) {
               ::qsnprintf(buf, sizeof(buf), "0x%4.4X", cpu.segReg[i - IDC_CS_REG]);
            }
            else {
               ::qsnprintf(buf, sizeof(buf), "0x%08X", cpu.segBase[i - IDC_CS_BASE]);
            }
            SetDlgItemText(hwndDlg, i, buf);
         }
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDOK: //OK Button
               for (i = IDC_CS_REG; i <= IDC_GS_BASE; i++) {
//                  unsigned int newVal;
                  GetDlgItemText(hwndDlg, i, buf, 16);
                  unsigned int newVal = strtoul(buf, NULL, 0);
//                  sscanf(buf, "%X", &newVal);
                  if (i < IDC_CS_BASE) {
                     cpu.segReg[i  - IDC_CS_REG] = (short)newVal;
                  }
                  else {
                     cpu.segBase[i - IDC_CS_BASE] = newVal;
                  }
               }
               EndDialog(hwndDlg, 0);
               return TRUE;
            case IDCANCEL: //CANCEL Button
               EndDialog(hwndDlg, 0);
               return TRUE;
         }
   }
   return FALSE;
}

BOOL CALLBACK MemoryDlgProc(HWND hwndDlg, UINT message,
                            WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         char buf[16];
         for (int i = IDC_STACKTOP; i <= IDC_HEAPSIZE; i++) {
//            HWND ctl = GetDlgItem(hwndDlg, i);
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
         }
         segment_t *s = get_segm_by_name(".stack");
         segment_t *h = get_segm_by_name(".heap");
         ::qsnprintf(buf, sizeof(buf), "0x%08X", s->endEA);
         SetDlgItemText(hwndDlg, IDC_STACKTOP, buf);
         ::qsnprintf(buf, sizeof(buf), "0x%08X", s->endEA - s->startEA);
         SetDlgItemText(hwndDlg, IDC_STACKSIZE, buf);
         ::qsnprintf(buf, sizeof(buf), "0x%08X", h->startEA);
         SetDlgItemText(hwndDlg, IDC_HEAPBASE, buf);
         ::qsnprintf(buf, sizeof(buf), "0x%08X", h->endEA - h->startEA);
         SetDlgItemText(hwndDlg, IDC_HEAPSIZE, buf);
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
         case IDOK: {//OK Button
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
               EndDialog(hwndDlg, 0);
               return TRUE;
            }
         case IDCANCEL: //Cancel Button
            EndDialog(hwndDlg, 0);
            return TRUE;
         }
   }
   return FALSE;
}

//ask user for an file name and load the file into memory
//at the specified address
char *getOpenFileName(const char *title, char *fileName, int nameLen, const char *filter, char *initDir) {
   OPENFILENAME ofn;
   if (fileName == NULL || nameLen == 0) {
      return NULL;
   }
   memset(&ofn, 0, sizeof(ofn));

   // Initialize OPENFILENAME
   ofn.lStructSize = sizeof(ofn);
   ofn.hwndOwner = x86Dlg;
   ofn.lpstrFile = fileName;
   //
   // Set lpstrFile[0] to '\0' so that GetOpenFileName does not
   // use the contents of szFile to initialize itself.
   //
//   *fileName = '\0';
   ofn.nMaxFile = nameLen;
   ofn.lpstrFilter = filter;
   ofn.nFilterIndex = 1;
   ofn.lpstrFileTitle = NULL;
   ofn.nMaxFileTitle = 0;
   ofn.lpstrInitialDir = initDir;
   ofn.lpstrTitle = title;
   ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
   if (GetOpenFileName(&ofn)) {
      return fileName;
   }
   return NULL;
}

BOOL CALLBACK SetMemoryDlgProc(HWND hwndDlg, UINT message,
                               WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         char buf[32];
         ::qsnprintf(buf, sizeof(buf), "0x%08X", (unsigned int)get_screen_ea());
         SendDlgItemMessage(hwndDlg, IDC_MEM_ADDR, WM_SETFONT, (WPARAM)fixed, FALSE);
         SendDlgItemMessage(hwndDlg, IDC_MEM_VALUES, WM_SETFONT, (WPARAM)fixed, FALSE);
         SetDlgItemText(hwndDlg, IDC_MEM_ADDR, buf);
         SetDlgItemText(hwndDlg, IDC_MEM_VALUES, "");
         CheckRadioButton(hwndDlg, IDC_HEX_BYTES, IDC_MEM_LOADFILE, IDC_HEX_DWORDS);
         return TRUE;
      }
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
         case IDOK: {//OK Button
               unsigned int btn;
               unsigned int addr = getEditBoxInt(hwndDlg, IDC_MEM_ADDR);
               unsigned int len = SendDlgItemMessage(hwndDlg, IDC_MEM_VALUES, WM_GETTEXTLENGTH, (WPARAM)0, (LPARAM)0);
               char *vals = (char*) malloc(len + 1);
               char *v = vals;
               GetDlgItemText(hwndDlg, IDC_MEM_VALUES, vals, len + 1);
               vals[len] = 0;
               for (btn = IDC_HEX_BYTES; btn <= IDC_MEM_LOADFILE; btn++) {
                  if (IsDlgButtonChecked(hwndDlg, btn) == BST_CHECKED) break;
               }
               switch (btn) {
               case IDC_MEM_LOADFILE:
                  memLoadFile(addr);
                  break;
               case IDC_MEM_ASCII: case IDC_MEM_ASCIIZ:
                  while (*v) writeMem(addr++, *v++, SIZE_BYTE);
                  if (btn == IDC_MEM_ASCIIZ) writeMem(addr, 0, SIZE_BYTE);
                  break;
               case IDC_HEX_BYTES: case IDC_HEX_WORDS: case IDC_HEX_DWORDS: {
                     unsigned int sz = btn - IDC_HEX_BYTES + 1;
                     char *ptr;
                     while (ptr = strchr(v, ' ')) {
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
                     break;
                  }
               }
               free(vals);
               EndDialog(hwndDlg, 0);
               return TRUE;
            }
         case IDCANCEL: //Cancel Button
            EndDialog(hwndDlg, 0);
            return TRUE;
         }
   }
   return FALSE;
}

void showInformationMessage(const char *title, const char *msg) {
   MessageBox(x86Dlg, msg, title, MB_OK);
}

bool getMmapBlockData(unsigned int *base, unsigned int *size) {
   char msg_buf[128];
   int result = DialogBox(hModule, MAKEINTRESOURCE(IDD_MMAP),
                          x86Dlg, MmapDlgProc);
   if (result == 2) {
      char *endptr;
      *size = strtoul(mmap_size, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid mmap size: %s, cancelling mmap allocation", mmap_size);
         showErrorMessage(msg_buf);
         return false;
      }
      *base = strtoul(mmap_base, &endptr, 0);
      if (*endptr) {
         ::qsnprintf(msg_buf, sizeof(msg_buf), "Invalid mmap base: %s, cancelling mmap allocation", mmap_base);
         showErrorMessage(msg_buf);
         return false;
      }
      return true;
   }
   return false;
}

static HCURSOR old;

void showWaitCursor() {
   old = SetCursor(waitCursor);
}

void restoreCursor() {
   SetCursor(old);
}

//This is the main callback function for the emulator interface
BOOL CALLBACK DlgProc(HWND hwndDlg, UINT message,
                      WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG: {
         x86Dlg = hwndDlg;
         setTitle();
         waitCursor = LoadCursor(NULL, IDC_WAIT);
         for (int i = IDC_EAX; i <= IDC_EFLAGS; i++) {
            HWND ctl = GetDlgItem(hwndDlg, i);
            editBoxes[i - IDC_EAX] = ctl;
            oldProc = SetWindowLong(ctl, GWL_WNDPROC, (LONG) EditSubclassProc);
            SendDlgItemMessage(hwndDlg, i, WM_SETFONT, (WPARAM)fixed, FALSE);
         }
         SendDlgItemMessage(hwndDlg, IDC_MEMORY, WM_SETFONT, (WPARAM)fixed, FALSE);
         syncDisplay();
         return TRUE;
      }
      case WM_CHAR:
         if (wParam == VK_CANCEL) {
            shouldBreak = 1;
         }
         break;
      case WM_COMMAND: {
         ThreadNode *currThread = activeThread;
         switch (LOWORD(wParam)) {
            case IDC_HEAP_LIST:
               dumpHeap();
               break;
            case IDC_RESET: //reset the display/emulator
               doReset();
               return TRUE;
            case IDC_STEP: //STEP
               stepOne();
               return TRUE;
            case IDC_JUMP_CURSOR: //Reset eip.cursor
               jumpToCursor();
               return TRUE;
            case IDC_RUN: {//Run
               run();
               return TRUE;
            }
            case IDC_SKIP: //Skip the next instruction
               skip();
               return TRUE;
            case IDC_RUN_TO_CURSOR: {//Run to cursor
               runToCursor();
               return TRUE;
            }
            case IDC_HIDE:
               ShowWindow(hwndDlg, SW_HIDE);
               return TRUE;
            case IDC_MEMORY:
               if (HIWORD(wParam) == LBN_DBLCLK) {
                  //modify stack contents in here
               }
               return TRUE;
            case IDC_SET_MEMORY:
               DialogBox(hModule, MAKEINTRESOURCE(IDD_SET_MEMORY),
                         x86Dlg, SetMemoryDlgProc);
               return TRUE;
            case IDC_PUSH:
               pushData();
               return TRUE;
            case IDC_DUMP:
               dumpRange();
               return TRUE;
            case IDC_DUMP_PE:
               dumpEmbededPE();
               return TRUE;
            case IDC_SEGMENTS:
               DialogBox(hModule, MAKEINTRESOURCE(IDD_SEGMENTDIALOG),
                         x86Dlg, SegmentDlgProc);
               return TRUE;
            case IDC_SETTINGS:
               DialogBox(hModule, MAKEINTRESOURCE(IDD_MEMORY),
                         x86Dlg, MemoryDlgProc);
               return TRUE;
            case IDC_TRACK: {
               HMENU menu = GetMenu(x86Dlg);
               if (getTracking()) {
                  CheckMenuItem(menu, IDC_TRACK, MF_BYCOMMAND | MF_UNCHECKED);
               }
               else {
                  CheckMenuItem(menu, IDC_TRACK, MF_BYCOMMAND | MF_CHECKED);
               }
               setTracking(!getTracking());
               return TRUE;
            }
            case IDC_TRACE: {
               HMENU menu = GetMenu(x86Dlg);
               if (getTracing()) {
                  CheckMenuItem(menu, IDC_TRACE, MF_BYCOMMAND | MF_UNCHECKED);
                  closeTrace();
               }
               else {
                  CheckMenuItem(menu, IDC_TRACE, MF_BYCOMMAND | MF_CHECKED);
                  openTraceFile();
               }
               setTracing(!getTracing());
               return TRUE;
            }            
            case IDC_LOGLIB: {
               HMENU menu = GetMenu(x86Dlg);
               if (logLibrary()) {
                  CheckMenuItem(menu, IDC_LOGLIB, MF_BYCOMMAND | MF_UNCHECKED);
               }
               else {
                  CheckMenuItem(menu, IDC_LOGLIB, MF_BYCOMMAND | MF_CHECKED);
               }
               setLogLibrary(!logLibrary());
               return TRUE;
            }
            case ID_EMULATE_BREAKONEXCEPTIONS: {
               HMENU menu = GetMenu(x86Dlg);
               if (breakOnExceptions) {
                  CheckMenuItem(menu, ID_EMULATE_BREAKONEXCEPTIONS, MF_BYCOMMAND | MF_UNCHECKED);
               }
               else {
                  CheckMenuItem(menu, ID_EMULATE_BREAKONEXCEPTIONS, MF_BYCOMMAND | MF_CHECKED);
               }
               setBreakOnExceptions(!breakOnExceptions);
               return TRUE;
            }
            case IDC_LOADLIB: //load a library file into the database
               loadLibrary();
               return TRUE;
            case IDC_GPA: //set a GetProcAddress save point
               tagImportAddressSavePoint();
               return TRUE;
            case IDC_BREAKPOINT:
               setBreakpoint();
               return TRUE;
            case IDC_CLEARBREAK:
               clearBreakpoint();
               return TRUE;
            case IDC_MEMEX:
               generateMemoryException();
               return TRUE;
            case IDC_EXPORT:
               doExportLookup();
               return TRUE;
            case IDC_SWITCH: {
               DialogBox(hModule, MAKEINTRESOURCE(IDD_SWITCH_THREAD),
                         x86Dlg, SwitchThreadDlgProc);
               return TRUE;
            }
            case IDC_HEAP_BLOCK: {
               grabHeapBlock();
               return TRUE;
            }
            case IDC_STACK_BLOCK: {
               grabStackBlock();
               return TRUE;
            }
            case IDC_MMAP_BLOCK: {
               grabMmapBlock();
               return TRUE;
            }
            case ID_PUSH_PUSHMAINARGS: {
               buildMainArgs();
               return TRUE;
            }
            case ID_PUSH_PUSHWINMAINARGS: {
               buildWinMainArgs();
               return TRUE;
            }
            case ID_PUSH_PUSHDLLMAINARGS: {
               buildDllMainArgs();
               return TRUE;
            }
         }
      }
   }
   return FALSE;
}

//subclassing procedure for the register edit controls.  only want to catch
//double clicks here and open an edit window in response.  Otherwise, pass
//the message along
LRESULT EditSubclassProc(HWND hwndCtl, UINT message,
                         WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_LBUTTONDBLCLK:
         doubleClick(hwndCtl);
         return TRUE;
   }
   return CallWindowProc((WNDPROC) oldProc, hwndCtl, message, wParam, lParam);
}

//open an input dialog.  Use the globals, title, prompt, and initial to
//configure the dialog box.  return the user entry in global value
BOOL CALLBACK InputDlgProc(HWND hwndDlg, UINT message,
                           WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG:
         SendDlgItemMessage(hwndDlg, IDC_DATA, WM_SETFONT, (WPARAM)fixed, FALSE);
         SetDlgItemText(hwndDlg, IDC_MESSAGE, prompt);
         SetDlgItemText(hwndDlg, IDC_DATA, initial);
         SendMessage(hwndDlg, WM_SETTEXT, FALSE, (LPARAM)title);
         return TRUE;
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDC_DATA: //STEP
               return TRUE;
            case ID_OK: //STEP from cursor
               GetDlgItemText(hwndDlg, IDC_DATA, value, 80);
               EndDialog(hwndDlg, 2);
               return TRUE;
            case ID_CANCEL: //Run
               EndDialog(hwndDlg, -1);
               return TRUE;
         }
   }
   return FALSE;
}

//open an mmap input dialog.
BOOL CALLBACK MmapDlgProc(HWND hwndDlg, UINT message,
                           WPARAM wParam, LPARAM lParam) {
   switch (message) {
      case WM_INITDIALOG:
         SendDlgItemMessage(hwndDlg, IDC_MMAP_SIZE, WM_SETFONT, (WPARAM)fixed, FALSE);
         SetDlgItemInt(hwndDlg, IDC_MMAP_BASE, 0, FALSE);
         SetDlgItemText(hwndDlg, IDC_MMAP_SIZE, "0x1000");
         return TRUE;
      case WM_COMMAND:
         switch (LOWORD(wParam)) {
            case IDC_MMAP_BASE:
               return TRUE;
            case IDC_MMAP_SIZE:
               return TRUE;
            case ID_OK:
               GetDlgItemText(hwndDlg, IDC_MMAP_BASE, mmap_base, 80);
               GetDlgItemText(hwndDlg, IDC_MMAP_SIZE, mmap_size, 80);
               EndDialog(hwndDlg, 2);
               return TRUE;
            case ID_CANCEL: //Run
               EndDialog(hwndDlg, -1);
               return TRUE;
         }
   }
   return FALSE;
}

bool createEmulatorWindow() {
   if (mainWindow == NULL) {
      mainWindow = (HWND)callui(ui_get_hwnd).vptr;
   }
   if (hModule == NULL) {
      hModule = GetModuleHandle("x86emu.plw");
      fixed = (HFONT)GetStockObject(ANSI_FIXED_FONT);
   }
   x86Dlg = CreateDialog(hModule, MAKEINTRESOURCE(IDD_EMUDIALOG),
                         mainWindow, DlgProc);
   return x86Dlg != NULL;
}

void destroyEmulatorWindow() {
   DestroyWindow(x86Dlg);
   x86Dlg = NULL;
}

void displayEmulatorWindow() {
   ShowWindow(x86Dlg, SW_SHOW);
}
