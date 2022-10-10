/*
   Source for x86 emulator IdaPro plugin
   File: hooklist.h
   Copyright (c) 2004-2022, Chris Eagle
   
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

#ifndef __HOOK_LIST_H
#define __HOOK_LIST_H

#include "buffer.h"

typedef void (*hookfunc)(unsigned int addr);

/*
 * These are used to setup hooking dialog menu entries
 */
typedef struct _HookEntry_t {
   const char *fName;
   hookfunc func;
} HookEntry;

extern HookEntry hookTable[];

class HookNode {
   friend hookfunc addHook(const char *fName, unsigned int funcAddr, hookfunc func, unsigned int id);
   friend void removeHook(unsigned int funcAddr);
   friend void freeHookList();
   friend void loadHookList(Buffer &b);
   friend void saveHookList(Buffer &b);
   friend Buffer *getHookListBlob(Buffer &b);
   friend hookfunc findHookedFunc(unsigned int funcAddr);
   friend hookfunc findAvailableHookFunc(const char *funcName);
   friend HookNode *findHookByAddr(unsigned int addr);
   friend HookNode *findHookByName(const char *fName);
   friend HookNode *getNext(HookNode *n);

public:
   HookNode(const char *fName, unsigned int addr, hookfunc func, unsigned int id, HookNode *nxt);
   ~HookNode();
   unsigned int getAddr() {return funcAddr;}
   const char *getName() {return funcName;}

private:
   char *funcName;
   unsigned int funcAddr;
   hookfunc func;
   unsigned int moduleId;
   HookNode *next;
};

hookfunc addHook(const char *fName, unsigned int funcAddr, hookfunc func, unsigned int id);
HookNode *findHookByAddr(unsigned int addr);
void loadHookList(Buffer &b);
void saveHookList(Buffer &b);
hookfunc findHookedFunc(unsigned int funcAddr);
hookfunc findAvailableHookFunc(const char *funcName);

#endif

