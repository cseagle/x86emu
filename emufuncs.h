/*
   Source for x86 emulator IdaPro plugin
   File: emufuncs.h
   Copyright (c) 2004-2022 Chris Eagle
   
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

#ifndef __EMULATE_FUNCS_H
#define __EMULATE_FUNCS_H

#include <typeinf.hpp>
#include <segment.hpp>

#include <stdio.h>
#include <stdint.h>
#include "buffer.h"
#include "peutils.h"
#include "hooklist.h"

#include "sdk_versions.h"

#define CALL_CDECL 0
#define CALL_STDCALL 1

struct FunctionInfo {
   char *fname;
   unsigned int result;
   unsigned int stackItems;
   unsigned int callingConvention;
#if IDA_SDK_VERSION >= 650
   tinfo_t ftype;
#else
   const type_t *type;
   const p_list *fields;
#endif
   FunctionInfo *next;
};

void emu_lstrlen(unsigned int addr = 0);
void emu_lstrcpyW(unsigned int addr = 0);
void emu_lstrcpy(unsigned int addr = 0);
void emu_strcpy(unsigned int addr = 0);
void emu_strncpy(unsigned int addr = 0);
void emu_lstrcat(unsigned int addr = 0);
void emu_strcat(unsigned int addr = 0);
void emu_wcsset(unsigned int addr = 0);
void emu_strlwr(unsigned int addr);

void emu_CreateThread(unsigned int addr = 0);

void emu_HeapCreate(unsigned int addr = 0);
void emu_HeapDestroy(unsigned int addr = 0);
void emu_HeapAlloc(unsigned int addr = 0);
void emu_HeapFree(unsigned int addr = 0);
void emu_HeapSize(unsigned int addr = 0);
void emu_GetProcessHeap(unsigned int addr = 0);

void emu_GlobalAlloc(unsigned int addr = 0);
void emu_GlobalFree(unsigned int addr = 0);
void emu_GlobalLock(unsigned int addr = 0);

void emu_NtAllocateVirtualMemory(unsigned int addr = 0);
void emu_LdrLoadDll(unsigned int addr = 0);
void emu_LdrGetProcedureAddress(unsigned int addr = 0);

void emu_VirtualAlloc(unsigned int addr = 0);
void emu_VirtualFree(unsigned int addr = 0);
void emu_VirtualProtect(unsigned int addr = 0);
void emu_LocalLock(unsigned int addr = 0);
void emu_LocalUnlock(unsigned int addr = 0);
void emu_LocalAlloc(unsigned int addr = 0);
void emu_LocalReAlloc(unsigned int addr = 0);
void emu_LocalFree(unsigned int addr = 0);
void emu_GetProcAddress(unsigned int addr = 0);
void emu_GetModuleHandleA(unsigned int addr = 0);
void emu_GetModuleHandleW(unsigned int addr = 0);
void emu_FreeLibrary(unsigned int addr = 0);
void emu_LoadLibraryA(unsigned int addr = 0);
void emu_LoadLibraryW(unsigned int addr = 0);
void emu_LoadLibraryExA(unsigned int addr = 0);
void emu_LoadLibraryExW(unsigned int addr = 0);

void emu_malloc(unsigned int addr = 0);
void emu_calloc(unsigned int addr = 0);
void emu_realloc(unsigned int addr = 0);
void emu_free(unsigned int addr = 0);

void emu_IsDebuggerPresent(unsigned int addr = 0);
void emu_CheckRemoteDebuggerPresent(unsigned int addr = 0);

void emu_CloseHandle(unsigned int addr = 0);
void emu_NtQuerySystemInformation(unsigned int addr = 0);
void emu_NtQueryInformationProcess(unsigned int addr = 0);
void emu_NtSetInformationThread(unsigned int addr = 0);
void emu_GetCurrentProcessId(unsigned int addr = 0);
void emu_GetCurrentProcess(unsigned int addr = 0);
void emu_GetCurrentThreadId(unsigned int addr = 0);
void emu_GetThreadContext(unsigned int addr = 0);

void emu_RevertToSelf(unsigned int addr);
void emu_AreAnyAccessesGranted(unsigned int addr);
void emu_GetBkMode(unsigned int addr);
void emu_GdiFlush(unsigned int addr);
void emu_GetROP2(unsigned int addr);
void emu_GetBkColor(unsigned int addr);
void emu_GdiGetBatchLimit(unsigned int addr);

void emu_StrChrIW(unsigned int addr);
void emu_StrChrIA(unsigned int addr);
void emu_StrCmpIW(unsigned int addr);
void emu_StrCmpNIW(unsigned int addr);
void emu_StrCmpW(unsigned int addr);
void emu_StrCmpNW(unsigned int addr);
void emu_StrCpyW(unsigned int addr);
void emu_StrSpnA(unsigned int addr);
void emu_StrCSpnIA(unsigned int addr);
void emu_StrCSpnIW(unsigned int addr);

void emu_GetACP(unsigned int addr);
void emu_GetClientRect(unsigned int addr);
void emu_IsCharUpperA(unsigned int addr);
void emu_IsCharAlphaA(unsigned int addr);
void emu_GetIconInfo(unsigned int addr);
void emu_GetWindow(unsigned int addr);
void emu_IsChild(unsigned int addr);
void emu_GetTopWindow(unsigned int addr);
void emu_GetWindowContextHelpId(unsigned int addr);
void emu_WindowFromDC(unsigned int addr);
void emu_GetWindowPlacement(unsigned int addr);
void emu_CopyIcon(unsigned int addr);
void emu_IsIconic(unsigned int addr);
void emu_GetGUIThreadInfo(unsigned int addr);
void emu_GetDC(unsigned int addr);
void emu_GetTitleBarInfo(unsigned int addr);
void emu_IsWindowUnicode(unsigned int addr);
void emu_IsMenu(unsigned int addr);
void emu_GetWindowRect(unsigned int addr);
void emu_IsWindowVisible(unsigned int addr);
void emu_GetForegroundWindow(unsigned int addr);
void emu_InSendMessage(unsigned int addr);
void emu_GetWindowTextA(unsigned int addr);
void emu_IsUserAnAdmin(unsigned int addr);

void emu_GetVersionExA(unsigned int addr);
void emu_GetVersion(unsigned int addr);
void emu_GetTickCount(unsigned int addr);

void emu_GetSystemTimeAsFileTime(unsigned int addr);
void emu_QueryPerformanceCounter(unsigned int addr);

void emu_InterlockedIncrement(unsigned int addr);
void emu_InterlockedDecrement(unsigned int addr);
void emu_EncodePointer(unsigned int addr);
void emu_DecodePointer(unsigned int addr);

void emu_InitializeCriticalSection(unsigned int addr);
void emu_InitializeCriticalSectionAndSpinCount(unsigned int addr);
void emu_TryEnterCriticalSection(unsigned int addr);
void emu_EnterCriticalSection(unsigned int addr);
void emu_LeaveCriticalSection(unsigned int addr);
void emu_DeleteCriticalSection(unsigned int addr);

void emu_AddVectoredExceptionHandler(unsigned int addr);
void emu_RemoveVectoredExceptionHandler(unsigned int addr);

void emu_Sleep(unsigned int addr);

void emu_GetLastError(unsigned int addr);
void emu_SetLastError(unsigned int addr);

void emu_TlsAlloc(unsigned int addr);
void emu_TlsFree(unsigned int addr);
void emu_TlsGetValue(unsigned int addr);
void emu_TlsSetValue(unsigned int addr);

void emu_FlsAlloc(unsigned int addr);
void emu_FlsFree(unsigned int addr);
void emu_FlsGetValue(unsigned int addr);
void emu_FlsSetValue(unsigned int addr);

void emu_GetEnvironmentStringsA(unsigned int addr);
void emu_GetEnvironmentStringsW(unsigned int addr);
void emu_FreeEnvironmentStringsA(unsigned int addr);
void emu_FreeEnvironmentStringsW(unsigned int addr);
void emu_GetCommandLineA(unsigned int addr);
void emu_GetCommandLineW(unsigned int addr);

void emu_GetStdHandle(unsigned int addr);
void emu_GetStartupInfoA(unsigned int addr);
void emu_GetStartupInfoW(unsigned int addr);

void emu_GetCPInfo(unsigned int addr);
void emu_WideCharToMultiByte(unsigned int addr);
void emu_MultiByteToWideChar(unsigned int addr);
void emu_GetStringTypeW(unsigned int addr);
void emu_GetStringTypeA(unsigned int addr);
void emu_LCMapStringW(unsigned int addr);
void emu_LCMapStringA(unsigned int addr);

void emu_GetLocaleInfoA(unsigned int addr);
void emu_GetLocaleInfoW(unsigned int addr);

void emu_GetWindowsDirectoryA(unsigned int addr);
void emu_GetWindowsDirectoryW(unsigned int addr);
void emu_GetSystemDirectoryA(unsigned int addr);
void emu_GetSystemDirectoryW(unsigned int addr);

unsigned int addHeapCommon(unsigned int maxSize, unsigned int base = 0);

void syscall();
void linuxSysenter();
void windowsSysenter();

void makeImportLabel(unsigned int addr, unsigned int val);
void saveModuleList(Buffer &b);
void loadModuleList(Buffer &b);
void saveModuleData(Buffer &b);
void loadModuleData(Buffer &b);

struct HandleNode {
   char *moduleName;
   unsigned int handle;
   unsigned int id;
   unsigned int maxAddr;
   unsigned int ordinal_base;
   unsigned int NoF;  //NumberOfFunctions
   unsigned int NoN;  //NumberOfNames
   unsigned int eat;  //AddressOfFunctions  export address table
   unsigned int ent;  //AddressOfNames      export name table
   unsigned int eot;  //AddressOfNameOrdinals  export ordinal table
   HandleNode *next;
};

unsigned int getHandle(HandleNode *m);
unsigned int getModuleEnd(unsigned int handle);
unsigned int getId(HandleNode *m);
HandleNode *addModule(const char *mod, bool loading, int id, bool addToPeb = true);
void addModuleToPeb(unsigned int handle, const char *name, bool loading = false);
void addModuleToPeb(HandleNode *hn, bool loading, unsigned int unicodeName = 0);
HandleNode *addNewModuleNode(const char *mod, unsigned int h, unsigned int id);

hookfunc checkForHook(char *funcName, unsigned int funcAddr, unsigned int moduleId);
void doImports(unsigned int import_drectory, unsigned int size, unsigned int image_base);
void doImports(PETables &pe);
bool isModuleAddress(unsigned int addr);
char *reverseLookupExport(unsigned int addr);

FunctionInfo *getFunctionInfo(const char *name);
void clearFunctionInfoList(void);
void addFunctionInfo(const char *name, unsigned int result, unsigned int nitems, unsigned int callType);
void saveFunctionInfo(Buffer &b);
void loadFunctionInfo(Buffer &b);
char *getFunctionPrototype(FunctionInfo *f);
char *getFunctionReturnType(FunctionInfo *f);

char *getString(unsigned int addr);
void init_til(const char *tilFile);

typedef void (*unemulatedCB)(unsigned int addr, const char *name);

void setUnemulatedCB(unemulatedCB cb);

unsigned int myGetProcAddress(unsigned int hModule, unsigned int lpProcName);
unsigned int myGetProcAddress(unsigned int hModule, const char *procName);
unsigned int myGetModuleHandle(const char *modName);

typedef enum {NEVER, ASK, ALWAYS} emu_Actions;

extern int emu_alwaysLoadLibrary;
extern int emu_alwaysGetModuleHandle;
extern unsigned int pCmdLineA;

bool is_valid_address(uint32_t addr);

void init_cgc_random(unsigned char *seed, unsigned int slen);
void save_cgc_rand_state();
bool restore_cgc_rand_state();
void init_negotiator(unsigned char *seed, uint32_t slen);
unsigned int cgc_random(unsigned int buf, unsigned int count, unsigned int rnd_bytes = 0);
bool cgc_global_init(const char *seed, const char *nseed, const char *host, uint16_t port, uint32_t bin_type);
void cgc_cleanup();
extern bool is_cgc_pov;

#endif
