/*
   Source for x86 emulator IdaPro plugin
   File: seh.cpp
   Copyright (c) 2004-2010, Chris Eagle
   
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

#include "cpu.h"
#include "seh.h"

static int seh_enable = 0;
static WIN_CONTEXT ctx;

typedef struct _VehNode {
   unsigned int handler;
   struct _VehNode *next;
} VehNode;

static VehNode *vehList;

struct WIN_CONTEXT *getContext() {
   return &ctx;
}

int usingSEH() {
   return seh_enable;
}

VehNode *findVehHandler(unsigned int handler) {
   for (VehNode *h = vehList; h; h = h->next) {
      if (h->handler == handler) {
         return h;
      }
   }
   return NULL;
}

void saveSEHState(Buffer &b) {
   int dummy;
   b.write(&dummy, sizeof(dummy));
   b.write(&seh_enable, sizeof(seh_enable));
   b.write(&ctx, sizeof(ctx));
}

void loadSEHState(Buffer &b) {
   unsigned int dummy;
   b.read(&dummy, sizeof(dummy));
   b.read(&seh_enable, sizeof(seh_enable));
   b.read(&ctx, sizeof(ctx));
}

void saveVEHState(Buffer &b) {
   for (VehNode *v = vehList; v; v = v->next) {
      b.write(&v->handler, sizeof(unsigned int));
   }
}

void loadVEHState(Buffer &b) {
   unsigned int dummy;
   while (b.read(&dummy, sizeof(dummy)) == 0) {
      addVectoredExceptionHandler(0, dummy);
   }
   b.reset_error();
}

//Copy current CPU state into CONTEXT structure for Windows Exception Handling
//Note that the global ctx struct is the only place that Debug and Floating
//point registers are currently defined
void cpuToContext() {
   regsToContext(&cpu, &ctx);
   ctx.Eip = cpu.initial_eip;  //use address at which exception occurred
}

//Copy from CONTEXT structure into CPU state for Windows Exception Handling
//Note that the global ctx struct is the only place that Debug and Floating
//point registers are currently defined
void contextToCpu() {
   contextToRegs(&ctx, &cpu);
}

void initContext() {
   initContext(&ctx);
}

void popContext() {
   unsigned char *ptr = (unsigned char*) &ctx;
   unsigned int addr, i;
   unsigned int ctx_size = (sizeof(WIN_CONTEXT) + 3) & ~3;  //round up to next unsigned int
   addr = esp;
   for (i = 0; i < sizeof(WIN_CONTEXT); i++) {
      *ptr++ = (unsigned char) readMem(addr++, SIZE_BYTE);
   }
   esp += ctx_size;
   contextToCpu();
}

void getContextToMem(unsigned int addr) {
//   unsigned char *ptr = (unsigned char*) &ctx;
   cpuToContext();
   copyContextToMem(&ctx, addr);
}

unsigned int pushContext() {
   unsigned int ctx_size = (sizeof(WIN_CONTEXT) + 3) & ~3;  //round up to next unsigned int
   unsigned int addr = esp - ctx_size;
   getContextToMem(addr);
   esp = addr;
   return esp;
}

void popExceptionRecord(EXCEPTION_RECORD *rec) {
   unsigned char *ptr = (unsigned char*) &rec;
   unsigned int addr, i;
   unsigned int rec_size = (sizeof(EXCEPTION_RECORD) + 3) & ~3;  //round up to next unsigned int
   addr = esp;
   for (i = 0; i < sizeof(EXCEPTION_RECORD); i++) {
      *ptr++ = (unsigned char) readMem(addr++, SIZE_BYTE);
   }
   esp += rec_size;
}

unsigned int pushExceptionRecord(EXCEPTION_RECORD *rec) {
   unsigned char *ptr = (unsigned char*) rec;
   unsigned int addr, i;
   unsigned int rec_size = (sizeof(EXCEPTION_RECORD) + 3) & ~3;  //round up to next unsigned int
   addr = esp -= rec_size;
   for (i = 0; i < sizeof(EXCEPTION_RECORD); i++) {
      writeMem(addr++, *ptr++, SIZE_BYTE);
   }
   return esp;
}

void doSehException(EXCEPTION_RECORD *rec) {
   unsigned int err_ptr = readMem(fsBase, SIZE_DWORD);
   unsigned int handler = readMem(err_ptr + 4, SIZE_DWORD);  //err->handler
   
   //do sanity checks on handler here?
   
   cpuToContext();
   unsigned int ctx_ptr = pushContext();
   unsigned int rec_ptr = pushExceptionRecord(rec);
   
   push(ctx_ptr, SIZE_DWORD);
   push(err_ptr, SIZE_DWORD);       //err_ptr == fsBase??
   push(rec_ptr, SIZE_DWORD);
   push(SEH_MAGIC, SIZE_DWORD);             //handler return address
//need to execute exception handler here setup flag to trap ret
//set eip to start of exception handler and resume fetching
   cpu.eip = handler;
}

static unsigned int currentVehHandler;

void doVehException(EXCEPTION_RECORD *rec, unsigned int handler) {      
   cpuToContext();
   unsigned int ctx_ptr = pushContext();
   unsigned int rec_ptr = pushExceptionRecord(rec);
   
   push(ctx_ptr, SIZE_DWORD);
   push(rec_ptr, SIZE_DWORD);
   push(esp, SIZE_DWORD);
   push(VEH_MAGIC, SIZE_DWORD);             //handler return address
//need to execute exception handler here setup flag to trap ret
//set eip to start of exception handler and resume fetching
   cpu.eip = handler;
}

void doException(EXCEPTION_RECORD *rec) {
   if (vehList) {
      if (currentVehHandler == 0) {
         currentVehHandler = vehList->handler;
         doVehException(rec, currentVehHandler);
      }
      else {
         VehNode *v = findVehHandler(currentVehHandler);
         if (v) {
            v = v->next;
         }
         if (v) {
            currentVehHandler = v->handler;
            doVehException(rec, currentVehHandler);
         }
         else {
            currentVehHandler = 0xffffffff;
         }
      }
   }
   else {
      currentVehHandler = 0xffffffff;
   }   
   if (currentVehHandler == 0xffffffff) {
      doSehException(rec);
   }   
}

void sehReturn() {
   EXCEPTION_RECORD rec;
   
   //need to check eax here to see if exception was handled
   //or if it needs to be kicked up to next SEH handler
   
   esp += 3 * SIZE_DWORD;  //clear off exception pointers
   
   popExceptionRecord(&rec);

   popContext();
   contextToCpu();
   //eip is now restored to pre exception location
   
   //need to fake an iret here
   doInterruptReturn();  //this clobbers EIP, CS, EFLAGS
   //so restore them here from ctx values
   cpu.eip = ctx.Eip;
   cpu.eflags = ctx.EFlags;
   _cs = ctx.SegCs;
   msg("Performing SEH return\n");
   currentVehHandler = 0;
}

void vehReturn() {
   EXCEPTION_RECORD rec;
   
   //need to check eax here to see if exception was handled
   //or if it needs to be kicked up to next SEH handler
   unsigned int res = eax;
   
   esp += 3 * SIZE_DWORD;  //clear off exception pointers
   
   popExceptionRecord(&rec);

   popContext();
   contextToCpu();
   //eip is now restored to pre exception location
   
   //need to fake an iret here
   doInterruptReturn();  //this clobbers EIP, CS, EFLAGS
   //so restore them here from ctx values
   cpu.eip = ctx.Eip;
   cpu.eflags = ctx.EFlags;
   _cs = ctx.SegCs;
   msg("Performing VEH return\n");

   if (res == EXCEPTION_CONTINUE_EXECUTION) {
      currentVehHandler = 0;
   }
   else {  //res == EXCEPTION_CONTINUE_SEARCH
      doException(&rec);
   }
}

void generateException(unsigned int code) {
   if (seh_enable) {
      EXCEPTION_RECORD rec;
      rec.exceptionCode = code;
      rec.exceptionFlags = CONTINUABLE;   //nothing sophisticated here
      rec.exceptionRecord = 0;   //NULL
      rec.exceptionAddress = cpu.initial_eip;
      rec.numberParameters = 0;
      doException(&rec);
   }
}

void breakpointException() {
   generateException(BREAKPOINT_EXCEPTION);
}

void debugException() {
   generateException(DEBUG_EXCEPTION);
}

void divzeroException() {
   generateException(DIV_ZERO_EXCEPTION);
}

void memoryAccessException() {
   generateException(MEM_ACCESS);
}

void IllegalOpcodeException() {
   generateException(UNDEFINED_OPCODE_EXCEPTION);
}

void enableSEH() {
   initContext();
   seh_enable = 1;
}

void sehBegin(unsigned int interrupt_number) {
   msg("Initiating SEH processing of INT %d\n", interrupt_number);
   switch (interrupt_number) {
   case 0:
      generateException(DIV_ZERO_EXCEPTION);
      break;   
   case 1:
      generateException(DEBUG_EXCEPTION);
      break;   
   case 3:
      generateException(BREAKPOINT_EXCEPTION);
      break;   
   case 6:
      generateException(UNDEFINED_OPCODE_EXCEPTION);
      break;   
   case 14:
      generateException(MEM_ACCESS);
      break;   
   }
}

void addVectoredExceptionHandler(bool first, unsigned int handler) {
   VehNode *n = (VehNode*)malloc(sizeof(VehNode));
   n->handler = handler;
   if (first) {
      n->next = vehList;
      vehList = n;
   }
   else {
      n->next = NULL;
      if (vehList) {
         VehNode *h;
         for (h = vehList; h->next; h = h->next) {}
         h->next = n;
      }
      else {
         vehList = n;
      }
   }
}

void removeVectoredExceptionHandler(unsigned int handler) {
   VehNode *p = NULL;
   for (VehNode *h = vehList; h->next; h = h->next) {
      if (h->handler == handler) {
         if (p) {
            p->next = h->next;
         }
         else {
            vehList = p->next;
         }
         free(h);
         break;
      }
      p = h;
   }
}
