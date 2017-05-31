/*
   Source for x86 emulator IdaPro plugin
   File: emuthreads.cpp
   Copyright (c) 2006-2010, Chris Eagle
   
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

#ifndef _MSC_VER
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif
#endif

#include "x86defs.h"
#include "emuthreads.h"
#include "seh.h"
#include "memmgr.h"

#include <segment.hpp>
#include <bytes.hpp>

#define DEFAULT_STACK_SIZE 0x100000

ThreadNode *threadList = NULL;
ThreadNode *activeThread = NULL;

/*
 * Figure out a new, unused thread id to assign to the new thread
 */
unsigned int getNewThreadHandle() {
   return threadList ? (threadList->handle + 4) : THREAD_HANDLE_BASE;  
}

/*
 * Figure out a new, unused thread id to assign to the new thread
 */
unsigned int getNewThreadId() {
   unsigned int tid = 0;
   do {
      getRandomBytes(&tid, 2);
      tid = (tid % 3000) + 1000;
      for (ThreadNode *tn = threadList; tn; tn = tn->next) {
         if (tn->id == tid) {
            tid = 0;
            break;
         }
      }
   } while (tid == 0);   
   return tid;
}

/*
 * we need to find a memory hole in which to allocate a new stack
 * for a new thread.  This is not a great algorithm, but it should 
 * work well enough for now.  Need to deconflict with heap space.
 * Should really rewrite to allocate space from emulation heap.
 * Should also look for holes created by destroyed threads
 */
unsigned int getNewStackLocation() {
   int count = 1;
   char buf[16];
   segment_t *s = get_segm_by_name(".stack");
   unsigned int top = (unsigned int)s->endEA + 0xFFFF;
   while (getseg(top)) {
      top += 0x10000;
      count++;
   }
   ::qsnprintf(buf, sizeof(buf), ".stack%d", count);
   MemMgr::mmap(top - 0xFFFF, 0x10000, 0, 0, buf);
   formatStack(top - 0xFFFF, top + 1);
   return top + 1;
}

/*
 * This constructor should be used for only one thread, the main thread
 * which is declared as a global in cpu.cpp
 */
ThreadNode::ThreadNode() {
   id = getNewThreadId();
   handle = getNewThreadHandle();
   hasStarted = 1;
   threadArg = 0;
   next = NULL;
}

ThreadNode::ThreadNode(unsigned int threadFunc, unsigned int threadArg) {
   next = NULL;
   id = getNewThreadId();
   handle = getNewThreadHandle();
   hasStarted = 0;
   regs = cpu;
   regs.eip = threadFunc;
   this->threadArg = threadArg;
   
   //create thread stack
   unsigned int top;
   regs.general[ESP] = top = getNewStackLocation();
   //the rest should really only be done for Windows binaries
   if (usingSEH()) {
      char buf[32];
      unsigned int teb = get_long(fsBase + TEB_LINEAR_ADDR);
      unsigned int peb = get_long(teb + TEB_PEB_PTR);
      unsigned int newTeb = 0x7ffdf000;
      unsigned int prev;
      do {
         prev = newTeb;
         if (newTeb == peb || newTeb == fsBase) {
            newTeb -= 0x1000;
         }
         else {
            for (ThreadNode *tn = threadList; tn; tn = tn->next) {
               if (newTeb == tn->regs.segBase[FS]) {
                  newTeb -= 0x1000;
               }
            }
         }
      } while (newTeb != prev);
      regs.segBase[FS] = newTeb;
      ::qsnprintf(buf, sizeof(buf), ".teb_%x", handle);
      if (getseg(newTeb)) {
         //clear previously used page
         for (int i = 0; i < 0x1000; i += 4) {
            patch_long(newTeb + i, 0);
         }
      }
      else {
         //map a page in for the new teb
         MemMgr::mmap(newTeb, 0x1000, 0, 0, buf);
      }
      regs.general[ESP] -= 32;
   }
}

ThreadNode::ThreadNode(Buffer &b, unsigned int /*currentActive*/) {
   next = NULL;
   b.read((char*)&handle, sizeof(handle));
   b.read((char*)&id, sizeof(id));
   b.read((char*)&hasStarted, sizeof(hasStarted));
   b.read((char*)&threadArg, sizeof(threadArg));
   b.read((char*)&regs, sizeof(regs));
}
   
void ThreadNode::save(Buffer &b, bool /*saveStack*/) {
   b.write((char*)&handle, sizeof(handle));
   b.write((char*)&id, sizeof(id));
   b.write((char*)&hasStarted, sizeof(hasStarted));
   b.write((char*)&threadArg, sizeof(threadArg));
   b.write((char*)&regs, sizeof(regs));
}

/*
 * return thread handle for new thread
 */
ThreadNode *emu_create_thread(unsigned int threadFunc, unsigned int threadArg) {
   ThreadNode *tn = new ThreadNode(threadFunc, threadArg);
   tn->next = threadList;
   threadList = tn;
   return tn;
}

/*
 * destroy the thread indicated by threadId.  Should add code to 
 * prevent destruction of the main thread
 * return the next thread to run (currently always the main thread)
 */
ThreadNode *emu_destroy_thread(unsigned int threadId) {
   ThreadNode *prev = NULL;
   ThreadNode *tn = NULL, *mainThread = NULL;
   for (tn = threadList; tn; tn = tn->next) {
      //doing the following test first prevents the main thread
      //from being destroyed
      if (tn->handle == THREAD_HANDLE_BASE) {
         mainThread = tn;
      }
      else if (tn->handle == threadId) {
         ThreadNode *delThread = tn;
         //free up thread stack
#ifdef SEGDEL_PERM      
         del_segm(tn->regs.general[ESP] - 1, SEGDEL_PERM | SEGDEL_SILENT);      
#else
         del_segm(tn->regs.general[ESP] - 1, 1);      
#endif
         if (prev) {
            prev->next = tn->next;
            tn = prev;
         }
         else {
            tn = threadList = tn->next;
         }
         msg("Destroyed thread 0x%x\n", tn->handle);
/*  //delete threads stack segment
         delete delThread->stack;
*/
         delete delThread;
      }
      prev = tn;
   }
   //cause a break since we are switching threads
   shouldBreak = 1;
   return mainThread;
}

/*
 * switch threads
 */
void emu_switch_threads(ThreadNode *new_thread) {
   if (activeThread != new_thread) {
      if (activeThread) {
         memcpy(&activeThread->regs, &cpu, sizeof(Registers));
      }
      activeThread = new_thread;
      memcpy(&cpu, &new_thread->regs, sizeof(Registers));
   
      if (!new_thread->hasStarted) {
         push(new_thread->threadArg, SIZE_DWORD);
         //push special thread return address
         push(THREAD_MAGIC, SIZE_DWORD);
         new_thread->hasStarted = 1;
      }
   }
}

/*
 * locate the thread with the given handle
 */
ThreadNode *findThread(unsigned int handle) {
   for (ThreadNode *tn = threadList; tn; tn = tn->next) {
      if (tn->handle == handle) return tn;
   }
   return NULL;
}

