/*
   Source for x86 emulator IdaPro plugin
   File: hooklist.cpp
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

#include <stdlib.h>
#include <string.h>

#include "x86defs.h"

#include "hooklist.h"

#ifndef NULL
#define NULL 0
#endif

static HookNode *hookList = NULL; 

HookNode::HookNode(const char *fName, unsigned int addr, hookfunc func, unsigned int id, HookNode *nxt) :
        funcAddr(addr), func(func), moduleId(id), next(nxt) {
   funcName = _strdup(fName);
}

HookNode::~HookNode() {
   free(funcName);
}

hookfunc addHook(const char *fName, unsigned int funcAddr, hookfunc func, unsigned int id) {
   hookList = new HookNode(fName, funcAddr, func, id, hookList);
   return func;
//   msg("x86emu: hooked %s at %X\n", fName, funcAddr);
}

void freeHookList() {
   for (HookNode *p = hookList; p; hookList = p) {
      p = p->next;
      delete hookList;
   }
   hookList = NULL;
}

void loadHookList(Buffer &b) {
   int n;
   freeHookList();
   b.read((char*)&n, sizeof(n));
   for (int i = 0; i < n; i++) {
      unsigned int addr;
      b.read((char*)&addr, sizeof(addr));
      char *name;
      b.readString(&name);
      hookfunc hf = findAvailableHookFunc(name);
      if (hf) {
         //need to find a way to pass valid id here
         msg("x86emu: Adding hook for %s at %X\n", name, addr);
         addHook(name, addr, hf, 0);
      }
      free(name);
   }
}

Buffer *getHookListBlob(Buffer &b) {
   Buffer *r = new Buffer();
   int n;
   b.read((char*)&n, sizeof(n));
   r->write((char*)&n, sizeof(n));
   for (int i = 0; i < n; i++) {
      unsigned int addr;
      b.read((char*)&addr, sizeof(addr));
      r->write((char*)&addr, sizeof(addr));
      char *name;
      b.readString(&name);
      r->writeString(name);
      free(name);
   }
   return r;
}

void saveHookList(Buffer &b) {
   int n = 0;
   HookNode *h;
   for (h = hookList; h; h = h->next) n++;
   b.write((char*)&n, sizeof(n));
   for (h = hookList; h; h = h->next) {
      b.write((char*)&h->funcAddr, sizeof(h->funcAddr));
      b.writeString(h->funcName);
   }
}

void removeHook(unsigned int funcAddr) {
   HookNode *prev = NULL, *curr = hookList;
   while (curr) {
      if (curr->funcAddr == funcAddr) {
         if (prev) {
            prev->next = curr->next;
         }
         else {
            hookList = curr->next;
         }
         delete curr;
         break;
      }
      prev = curr;
      curr = curr->next;
   }
}

hookfunc findHookedFunc(unsigned int funcAddr) {
   for (HookNode *n = hookList; n; n = n->next) {
      if (n->funcAddr == funcAddr) {
         return n->func;
      }
   }
   return NULL;
}

hookfunc findAvailableHookFunc(const char *funcName) {
   for (int i = 0; hookTable[i].fName; i++) {
      if (!strcmp(hookTable[i].fName, funcName)) return hookTable[i].func;
   }
   return NULL;
}

HookNode *findHookByAddr(unsigned int funcAddr) {
   for (HookNode *n = hookList; n; n = n->next) {
      if (n->funcAddr == funcAddr) {
         return n;
      }
   }
   return NULL;
}

HookNode *findHookByName(const char *fName) {
   for (HookNode *n = hookList; n; n = n->next) {
      if (!strcmp(n->funcName, fName)) {
         return n;
      }
   }
   return NULL;
}

HookNode *getNext(HookNode *n) {
   return n ? n->next : hookList;
}

