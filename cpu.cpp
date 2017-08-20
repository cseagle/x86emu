/*
   Source for x86 emulator
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

#include <stdio.h>
#include <stdint.h>
#define _USE_MATH_DEFINES
#include <math.h>

#include "cpu.h"
#include "seh.h"
#include "emuthreads.h"
#include "emuheap.h"
#include "memmgr.h"

#ifdef __IDP__
#include "hooklist.h"
#include "emufuncs.h"
#include <segment.hpp>
#endif

//masks to clear out bytes appropriate to the sizes above
unsigned int SIZE_MASKS[] = {0, 0x000000FF, 0x0000FFFF, 0, 0xFFFFFFFF};

//masks to limit bit rotation amount in rotation instructions
unsigned int ROTATE_SIZE_MASKS[] = {0, 7, 0xF, 0, 0x1F };

//masks to clear out bytes appropriate to the sizes above
unsigned int SIGN_BITS[] = {0, 0x00000080, 0x00008000, 0, 0x80000000};

//masks to clear out bytes appropriate to the sizes above
#if defined(CYGWIN) || !defined(WIN32)
unsigned long long CARRY_BITS[] = {0, 0x00000100, 0x00010000, 0, 0x100000000ll};
#else
unsigned long long CARRY_BITS[] = {0, 0x00000100, 0x00010000, 0, 0x100000000};
#endif

unsigned char BITS[] = {0, 8, 16, 0, 32};

const unsigned char parityValues[256] = {
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
   1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

//Mask for allowable setting of CPU flags
unsigned int current_priv_flags = RING_3_FLAGS;

//The cpu
Registers cpu;

//Floating Point registers

FloatingPointUnit fpu;

SSE2Registers sse2;

ll_union tsc; //timestamp counter

static unsigned int segmentBase;   //base address for next memory operation
static unsigned int segmentReg;   //base address for next memory operation

unsigned int seg3_map[] = {3, 0, 1, 2, 4, 5, 0, 0};

//Need to make this user configurable.  For now it is fixed.
static unsigned int maxStackSize = 0x100000;

static unsigned int instStart;
static unsigned int fpuStart;
//struct to describe an instruction being decoded
static AddrInfo source;
static AddrInfo dest;
static unsigned int opsize;  //operand size for this instruction
static unsigned int prefix;  //any prefix flags
static unsigned char opcode;   //opcode, first or second unsigned char (if first == 0x0F)

unsigned int importSavePoint = 0xFFFFFFFF;
static bool makeImport = false;

IntrRecord *intrList = NULL;

//flag to tell CPU users that they should probably break because something
//strange has happened
unsigned int shouldBreak = 1;

bool breakOnExceptions = true;

int doEscape();

#ifndef CYGWIN
// was added to work under Microsoft Visual Studio
long double remainderl(long double fpZero, long double fpOne) {
   return fpZero - (floor(fpZero / fpOne) * fpOne);
}

// was added to work under Microsoft Visual Studio
long double roundl(long double fpZero) {
   return floor(fpZero);
}
#endif

void fpuInit() {
   fpu.control = 0x37F;
   fpu.status = 0;
   fpu.tag = 0xFFFF;
   fpu.lastDataPointer = 0;
   fpu.lastDataSeg = 0;
   fpu.lastIP = 0;
   fpu.lastIPseg = 0;
   fpu.opcode = 0;
}

void fpuSetPointers(unsigned int data, unsigned short opcode) {
   fpu.lastIP = fpuStart;
   fpu.lastIPseg = _cs;
   fpu.lastDataPointer = data;
   fpu.lastDataSeg = segmentReg;
   fpu.opcode = opcode & 0x7FF;
}

unsigned int fpuGetTag(unsigned int n) {
   n &= 7;
   return (fpu.tag >> (n * 2)) & 3;
}

void fpuSetTag(unsigned int n, unsigned int tag) {
   n = (n * 2) & 0xF;
   fpu.tag &= ~(3 << n);   //clear old tag
   fpu.tag |= (tag & 3) << n;  //set new tag
}

void setFpuStackTop(unsigned int n) {
   fpu.status = (fpu.status & ~FPU_TOS) | ((n & 7) << 11);
}

void setFpuRegister(unsigned int reg, long double val) {
   reg &= 7;
   fpu.r[reg].fp = val;
   if (val == 0.0) {
      fpuSetTag(reg, FPU_ZERO_TAG);
   }
   else {
      fpuSetTag(reg, FPU_VALID_TAG);
   }
}

void fpuPush(long double n) {
   unsigned int tos = (fpuStackTop - 1) & 7;
   if (fpuGetTag(tos) != FPU_EMPTY_TAG) {
      FPU_SET(FPU_INVALID | FPU_STACKFAULT | FPU_C1);
      if (!FPU_MASK_GET(FPU_INVALID)) {
         //not masked
         FPU_SET(FPU_ERRORSUMMARY);
         return;
      }
   }
   else {
      FPU_CLEAR(FPU_C1);
   }
   setFpuRegister(tos, n);
   setFpuStackTop(tos);
}

long double fpuPop() {
   if (fpuGetTag(fpuStackTop) == FPU_EMPTY_TAG) {
      FPU_SET(FPU_INVALID | FPU_STACKFAULT);
      FPU_CLEAR(FPU_C1);
      if (!FPU_MASK_GET(FPU_INVALID)) {
         //not masked
         FPU_SET(FPU_ERRORSUMMARY);
         return 0.0;
      }
   }
   else {
      FPU_CLEAR(FPU_C1);
   }
   long double result = fpu.r[fpuStackTop].fp;
   fpuSetTag(fpuStackTop, FPU_EMPTY_TAG);
   unsigned int tos = (fpuStackTop + 1) & 7;
   setFpuStackTop(tos);
   return result;
}

long double fpuGet(int n) {
   int reg = (fpuStackTop + n) & 7;
   long double result = fpu.r[reg].fp;
   if (fpuGetTag(reg) == FPU_EMPTY_TAG) {
      FPU_SET(FPU_INVALID | FPU_STACKFAULT);
      FPU_CLEAR(FPU_C1);
   }
   return result;
}

void fpuSet(int n, long double val) {
   int reg = (fpuStackTop + n) & 7;
   setFpuRegister(reg, val);
}

void fpuCompare(long double d1, long double d2) {
   if (d1 < d2) {
      FPU_CLEAR(FPU_C3 | FPU_C2);
      FPU_SET(FPU_C0);
   }
   else if (d1 > d2) {
      FPU_CLEAR(FPU_C3 | FPU_C2 | FPU_C0);
   }
   else {
      FPU_CLEAR(FPU_C2 | FPU_C0);
      FPU_SET(FPU_C3);
   }
}

void fpuLoadEnv(unsigned int addr) {
   fpu.control = (unsigned short)readMem(addr, SIZE_WORD);
   addr += 4;
   fpu.status = (unsigned short)readMem(addr, SIZE_WORD);
   addr += 4;
   fpu.tag = (unsigned short)readMem(addr, SIZE_WORD);
   addr += 4;
   fpu.lastIP = (unsigned int)readMem(addr, SIZE_DWORD);
   addr += 4;
   unsigned int val = (unsigned int)readMem(addr, SIZE_DWORD);
   fpu.opcode = val >> 16;
   fpu.lastIPseg = val & 0xFFFF;
   addr += 4;
   fpu.lastDataPointer = (unsigned int)readMem(addr, SIZE_DWORD);
   addr += 4;
   fpu.lastDataSeg = (unsigned int)readMem(addr, SIZE_DWORD);
}

void fpuStoreEnv(unsigned int addr) {
   writeMem(addr, fpu.control, SIZE_DWORD);
   addr += 4;
   writeMem(addr, fpu.status, SIZE_DWORD);
   addr += 4;
   writeMem(addr, fpu.tag, SIZE_DWORD);
   addr += 4;
   writeMem(addr, fpu.lastIP, SIZE_DWORD);
   addr += 4;
   unsigned int opseg = fpu.opcode;
   writeMem(addr, fpu.lastIPseg | (opseg << 16), SIZE_DWORD);
   addr += 4;
   writeMem(addr, fpu.lastDataPointer, SIZE_DWORD);
   addr += 4;
   writeMem(addr, fpu.lastDataSeg, SIZE_DWORD);
}

void setInterruptGate(unsigned int base, unsigned int interrupt_number,
                      unsigned int segment, unsigned int handler) {
   segmentBase = dsBase;
   segmentReg = _ds;
   interrupt_number *= 8;
   writeMem(base + interrupt_number, handler, SIZE_WORD);
   writeMem(base + interrupt_number + 6, handler >> 16, SIZE_WORD);
   writeMem(base + interrupt_number + 2, segment, SIZE_WORD);
   writeMem(base + interrupt_number + 4, 0xEE00, SIZE_WORD);
}

void initIDTR(unsigned int idtBase, unsigned int idtLimit) {
   cpu.idtr.base = idtBase;
   cpu.idtr.limit = idtLimit;
   if (usingSEH()) {
      setInterruptGate(cpu.idtr.base, 0, _cs, SEH_MAGIC);
      setInterruptGate(cpu.idtr.base, 1, _cs, SEH_MAGIC);
      setInterruptGate(cpu.idtr.base, 3, _cs, SEH_MAGIC);
      setInterruptGate(cpu.idtr.base, 6, _cs, SEH_MAGIC);
      setInterruptGate(cpu.idtr.base, 14, _cs, SEH_MAGIC);
   }
   else {
      setInterruptGate(cpu.idtr.base, 0x80, _cs, INTx80_MAGIC);
   }
}

void initGDTR(unsigned int gdtBase, unsigned int gdtLimit) {
   cpu.gdtr.base = gdtBase;
   cpu.gdtr.limit = gdtLimit;
}

unsigned int getGdtDescBase(unsigned int desc) {
   desc *= 8;  //index into gdt
   if (desc < cpu.gdtr.limit) {
      unsigned int base = readDword(cpu.gdtr.base + desc);
      unsigned int d2 = readDword(cpu.gdtr.base + desc + 4);
      unsigned int d3 = (d2 & 0xFF) << 16;
      d2 &= 0xff000000;
      base >>= 16;
      base |= d2 | d3;
      return base;
   }
   else {
      //some sort of access violation
      return 0;
   }
}

unsigned int getGdtDescLimit(unsigned int desc) {
   desc *= 8;  //index into gdt
   if (desc < cpu.gdtr.limit) {
      unsigned int limit = readMem(cpu.gdtr.base + desc, SIZE_DWORD) & 0xffff;
      unsigned int d2 = readMem(cpu.gdtr.base + desc + 4, SIZE_DWORD) & 0xff0000;
      return limit | d2;
   }
   else {
      //some sort of access violation
      return 0;
   }
}

void setGdtDesc(unsigned int desc, unsigned int base, unsigned int limit) {
   desc *= 8;
   if (desc < cpu.gdtr.limit) {
      unsigned int d1 = (base << 16) | ((limit >> 16) & 0xffff);
      unsigned int d2 = ((base >> 16) & 0xff) | (base & 0xff000000) | (limit & 0xf0000);
      writeDword(cpu.gdtr.base + desc, d1);
      writeDword(cpu.gdtr.base + desc + 4, d2);
   }
   else {
      //some sort of access violation
   }   
}

#ifdef __IDP__

int saveState(netnode &f) {
   unsigned char *buf = NULL;
   unsigned int sz;
//   Buffer b(CPU_VERSION);
   Buffer b;
//   int personality = f.altval(HEAP_PERSONALITY);

   //need to start writing version magic as first 4 bytes
   //current registers for active thread are saved here
   b.write((char*)cpu.debug_regs, sizeof(cpu.debug_regs));
   b.write((char*)cpu.general, sizeof(cpu.general));
   b.write((char*)&cpu.initial_eip, sizeof(cpu.initial_eip));
   b.write((char*)&cpu.eip, sizeof(cpu.eip));
   b.write((char*)&cpu.eflags, sizeof(cpu.eflags));
   b.write((char*)&cpu.control, sizeof(cpu.control));
   b.write((char*)cpu.segBase, sizeof(cpu.segBase));
   b.write((char*)cpu.segReg, sizeof(cpu.segReg));
   b.write((char*)&cpu.gdtr, sizeof(cpu.gdtr));
   b.write((char*)&cpu.idtr, sizeof(cpu.idtr));
   b.write((char*)&tsc, sizeof(tsc));
   b.write((char*)&importSavePoint, sizeof(importSavePoint));

/*
   if (personality == 0) {
      if (HeapBase::getHeap()) {
         HeapBase::getHeap()->save(b);
      }
   }
   else {
*/
      //new style heaps are saved into a dedicated netnode
      if (HeapBase::getHeap()) {
         Buffer hb;
         netnode hn("$ X86emu Heap");
         hn.create("$ X86emu Heap");
         HeapBase::getHeap()->save(hb);
   
         if (!hb.has_error()) {
            unsigned char *hbuf = NULL;
            // Delete any previous blob data in the IDA database node.
            //
            hn.delblob(0, 'B');
            //
            // Convert the output blob object into a buffer and
            // store it in the database node.
            //
            unsigned int hsz = (unsigned int)hb.get_wlen();
         //   msg("x86emu: writing blob of size %d.\n", sz);
            hbuf = hb.get_buf();
            hn.setblob(hbuf, hsz, 0, 'B');
         }
         else {
            msg("X86 emu heap buffer error, unable to write heap data\n");
         }
      }
//   }

   saveHookList(b);
   saveModuleList(b);

   saveSEHState(b);

   ThreadNode *tn;
   unsigned int threadCount = 0;
   for (tn = threadList; tn; tn = tn->next) threadCount++;

   unsigned int threadMagic = THREAD_MAGIC;
   b.write((char*)&threadMagic, sizeof(threadMagic));
   b.write((char*)&activeThread->handle, sizeof(activeThread->handle));
   b.write((char*)&threadCount, sizeof(threadCount));

   //now save active thread data and thread list
   for (tn = threadList; tn; tn = tn->next) {
//      msg("x86emu: saving thread handle: %x, active handle: %x\n", tn->handle, activeThread->handle);
      tn->save(b, activeThread->handle != tn->handle);
   }

//   saveVEHState(b);

   if (!b.has_error()) {
   //
      // Delete any previous blob data in the IDA database node.
      //
      f.delblob(0, 'B');

      //
      // Convert the output blob object into a buffer and
      // store it in the database node.
      //
      sz = (unsigned int)b.get_wlen();
   //   msg("x86emu: writing blob of size %d.\n", sz);
      buf = b.get_buf();
/*
      for (int i = 0; i < sz; i += 16) {
         for (int j = 0; j < 16 && (j + i) < sz; j++) {
            msg("%2.2X ", buf[i + j]);
         }
         msg("\n");
      }
*/
      f.setblob(buf, sz, 0, 'B');

      //save fpu state
      f.setblob(&fpu, sizeof(fpu), 0, 'F');

      //save sse2 state
      f.setblob(&sse2, sizeof(sse2), 0, 'X');

      return X86EMUSAVE_OK;
   }
   else {
      return X86EMUSAVE_FAILED;
   }
}

int loadState(netnode &f) {
   unsigned char *buf = NULL;
   size_t sz;
//   int personality = f.altval(HEAP_PERSONALITY);
   // Fetch the blob attached to the node.
   if ((buf = (unsigned char *)f.getblob(NULL, &sz, 0, 'B')) == NULL) return X86EMULOAD_NO_NETNODE;
//   msg("x86emu: netnode found, sz = %d.\n", sz);
/*
   msg("netnode found, sz = %d.\n", sz);
   for (int i = 0; i < sz; i += 16) {
      for (int j = 0; j < 16 && (j + i) < sz; j++) {
         msg("%2.2X ", buf[i + j]);
      }
      msg("\n");
   }
*/
   Buffer b(buf, sz);
   //need to read version magic as first 4 bytes and skip stages depending on version
   b.read((char*)cpu.debug_regs, sizeof(cpu.debug_regs));
   b.read((char*)cpu.general, sizeof(cpu.general));
   b.read((char*)&cpu.initial_eip, sizeof(cpu.initial_eip));
   b.read((char*)&cpu.eip, sizeof(cpu.eip));
   b.read((char*)&cpu.eflags, sizeof(cpu.eflags));
   b.read((char*)&cpu.control, sizeof(cpu.control));
   b.read((char*)cpu.segBase, sizeof(cpu.segBase));
   b.read((char*)cpu.segReg, sizeof(cpu.segReg));
   b.read((char*)&cpu.gdtr, sizeof(cpu.gdtr));
   b.read((char*)&cpu.idtr, sizeof(cpu.idtr));
   b.read((char*)&tsc, sizeof(tsc));
   b.read((char*)&importSavePoint, sizeof(importSavePoint));

/*
   if (personality == 0) {
      EmuHeap::loadHeapLayout(b);
   }
   else {
*/
/*
      unsigned char *hbuf = NULL;
      size_t hsz;
      netnode hn("$ X86emu Heap");
      // Fetch the blob attached to the node.
      if ((hbuf = (unsigned char *)hn.getblob(NULL, &hsz, 0, 'B')) != NULL) {
         Buffer hb(hbuf, hsz);
         EmuHeap::loadHeapLayout(hb);
      }
      else {
         msg("x86emu: no heap data found in netnodes\n");
//         return X86EMULOAD_NO_NETNODE;
      }
*/
//   }

   loadHookList(b);
   loadModuleList(b);

/*
   if (b.getVersion() == 0) {
      Buffer *r = getHookListBlob(b);
//      loadHookList(b);           //this needs to happen after modules have been loaded in new scheme
      loadModuleList(b);
      loadHookList(*r);
      delete r;
   }
   else {
      loadModuleList(b);
      loadHookList(b);
   }
*/

   loadSEHState(b);

   //now load additional thread data and set active thread

   unsigned int threadMagic, threadCount, active;
   b.read((char*)&threadMagic, sizeof(threadMagic));
   if (threadMagic == THREAD_MAGIC) {
      b.read((char*)&active, sizeof(active));
      b.read((char*)&threadCount, sizeof(threadCount));
      //now load thread list
      ThreadNode *tn = NULL;
      for (unsigned int i = 0; i < threadCount; i++) {
         if (i == 0) {
            threadList = new ThreadNode(b, active);
            tn = threadList;
         }
         else {
            tn->next = new ThreadNode(b, active);
            tn = tn->next;
         }
         if (tn->handle == active) {
            activeThread = tn;
         }
      }
/*
      for (tn = threadList; tn; tn = tn->next) {
         msg("Thread: %x\n", tn->handle);
      }
      msg("x86emu: active: %x, active->handle: %x\n", activeThread, activeThread ? activeThread->handle : 0);
*/
      msg("x86emu: loaded %d threads from saved state\n", threadCount);
      
//      loadVEHState(b);
   }

/*
   if (!b.has_error() && cpu.idtr.base == 0) {
      initIDTR();
   }
*/
   qfree(buf);

   //read fpu state
   sz = sizeof(fpu);
   f.getblob(&fpu, &sz, 0, 'F');

   //read sse2 state
   sz = sizeof(sse2);
   f.getblob(&sse2, &sz, 0, 'X');

   return b.has_error() ? X86EMULOAD_CORRUPT : X86EMULOAD_OK;
}

#endif

void resetCpu() {
   memset(cpu.general, 0, sizeof(cpu.general));
   cpu.eip = 0xFFF0;
   //enable interrupts by default per Kris Kaspersky
   cpu.eflags = xIF | 2;
   cpu.gdtr.base = cpu.idtr.base = 0;
   cpu.gdtr.limit = cpu.idtr.limit = 0xFFFF;
   _cs = 0xF000;  //base = 0xFFFF0000, limit = 0xFFFF
   cr0 = 0x60000010;
   tsc.ll = 0;
   fpu.tag  = 0xFFFF;
   //need to clear the heap in here as well then allocate a new idt
}

void initProgram(unsigned int entry, unsigned int idtBase, unsigned int idtLimit) {
   cpu.eip = entry;
   initIDTR(idtBase, idtLimit);
}

//sign extension functions
//unsigned char->unsigned short
unsigned short sebw(unsigned char val) {
   short result = (char)val;
   return (unsigned short) result;
}

//unsigned short->unsigned int
unsigned int sewd(unsigned short val) {
   int result = (short)val;
   return (unsigned int) result;
}

//unsigned char->unsigned int
unsigned int sebd(unsigned char val) {
   int result = (char)val;
   return (unsigned int) result;
}

//unsigned int->unsigned long long
unsigned long long sedq(unsigned int val) {
   unsigned long long result = (int)val;
   return result;
}

//The stack is the only segment that can grow automatically to a
//predetermined maximum size, so we check here to see if a reference
//is being made to a location outside the currently allocated range
//of the stack segment and adjust the stack size accordingly.
bool checkStackRange(unsigned int addr) {
   segment_t *s = getseg(addr);
   if (s == NULL) {
      //addr may point outside any existing segment
      //check to see if it is in allowable range of
      //the stack segment, but not yet allocated
      segment_t *stack = get_segm_by_name(".stack");
      if (stack == NULL) {
         //no stack segment exists! Nothing to grow
         return false;
      }
      unsigned int pageBase = addr & ~0xFFF; //truncate to 4k boundary
      unsigned int minStack = (unsigned int)stack->endEA - maxStackSize;
      if (pageBase < stack->endEA && pageBase >= minStack) {
         set_segm_start(stack->startEA, pageBase, 0);
      }
      s = getseg(addr);
   }
   return s != NULL;
}

//return a unsigned char
unsigned char readByte(unsigned int addr) {
   if (getseg(addr) == NULL) {
      if (!isModuleAddress(addr)) {
         throw 14;  //page fault exception ??
      }
   }
   return get_byte(addr);
}

//don't interface to IDA's get_word/long routines so
//that we can detect stack usage in readByte
unsigned short readWord(unsigned int addr) {
   unsigned short result = readByte(addr + 1);
   result <<= 8;
   return result | readByte(addr);
}

unsigned int readDword(unsigned int addr) {
   unsigned int result = readWord(addr + 2);
   result <<= 16;
   return result | readWord(addr);
}

//all reads from memory should be through this function
unsigned int readMem(unsigned int addr, unsigned char size) {
   int result = 0;
   addr += segmentBase;
   switch (size) {
      case SIZE_BYTE:
         result = (int) readByte(addr);
         break;
      case SIZE_WORD:
         result = (int) readWord(addr);
         break;
      case SIZE_DWORD:
         result = (int) readDword(addr);
         break;
   }
   return result;
}

unsigned int readBuffer(unsigned int addr, void *buf, unsigned int nbytes) {
//   int result = 0;
   addr += segmentBase;
   for (unsigned int i = 0; i < nbytes; i++) {
      ((unsigned char*)buf)[i] = readByte(addr + i);
   }
   return nbytes;
}

//store a unsigned char
void writeByte(unsigned int addr, unsigned char val) {
   if (getseg(addr) == NULL) {
      if (!isModuleAddress(addr)) {
         throw 14;  //page fault exception ??
      }
   }
   //could also check write to read only page
   if (checkStackRange(addr)) {
      patch_byte(addr, val);
   }
}

//don't interface to IDA's put_word/long routines so
//that we can detect stack usage in writeByte
void writeWord(unsigned int addr, unsigned short val) {
   writeByte(addr, (unsigned char)val);
   writeByte(addr + 1, (unsigned char)(val >> 8));
}

void writeDword(unsigned int addr, unsigned int val) {
   if (makeImport) makeImportLabel(addr, val);
   writeWord(addr, (unsigned short)val);
   writeWord(addr + 2, (unsigned short)(val >> 16));
}

//all writes to memory should be through this function
void writeMem(unsigned int addr, unsigned int val, unsigned char size) {
   addr += segmentBase;
   switch (size) {
      case SIZE_BYTE:
         writeByte(addr, (unsigned char)val);
         break;
      case SIZE_WORD:
         writeWord(addr, (unsigned short)val);
         break;
      case SIZE_DWORD:
         writeDword(addr, val);
         break;
   }
}

unsigned int writeBuffer(unsigned int addr, void *buf, unsigned int nbytes) {
//   int result = 0;
   addr += segmentBase;
   for (unsigned int i = 0; i < nbytes; i++) {
      writeByte(addr + i, (unsigned char)((unsigned char*)buf)[i]);
   }
   return nbytes;
}

void push(unsigned int val, unsigned char size) {
   segmentBase = ssBase;
   segmentReg = _ss;
   esp -= size;
   writeMem(esp, val, size);
}

unsigned int pop(unsigned char size) {
   segmentBase = ssBase;
   segmentReg = _ss;
   unsigned int result = readMem(esp, size);
   esp += size;
   return result;
}

void doInterruptReturn() {
   if (intrList) {
      if (intrList->hasError) {
         pop(SIZE_DWORD);  //pop the saved error code
      }
      cpu.eip = pop(SIZE_DWORD);
      _cs = pop(SIZE_DWORD);
      cpu.eflags = pop(SIZE_DWORD);
      IntrRecord *temp = intrList;
      intrList = intrList->next;
      free(temp);
   }  //else no interrupts to return from!
}

void initiateInterrupt(unsigned int interrupt_number, unsigned int saved_eip) {
   unsigned int table = cpu.idtr.base + interrupt_number * 8;
   //need to pick segment reg value out of table as well
   unsigned int handler = readMem(table, SIZE_WORD);
   handler |= (readMem(table + 6, SIZE_WORD) << 16);
   if (breakOnExceptions) {
      shouldBreak = 1;
   }
   if (handler) {
      msg("x86emu: Initiating INT %d processing w/ handler %x\n", interrupt_number, handler);
      push(cpu.eflags, SIZE_DWORD);
      push(_cs, SIZE_DWORD);
      push(saved_eip, SIZE_DWORD);
      //need to push error code if required by interrupt_number
      //need to keep track of nested interrupts so that we know whether to
      //pop off the error code during the associated iret
      cpu.eip = handler;
      IntrRecord *temp = (IntrRecord*) calloc(1, sizeof(IntrRecord));
      temp->next = intrList;
      intrList = temp;
      if (handler == SEH_MAGIC) {
         sehBegin(interrupt_number);
      }
      else if (handler == INTx80_MAGIC) {
         //should distinguish between Linux and FreeBSD then read eax
         //and perform some action
         //override breakOnExceptions in the special case of a syscall 
         shouldBreak = doBreakOnSyscall;
         syscall();
         cpu.eip = pop(SIZE_DWORD);
         _cs = pop(SIZE_DWORD);
         cpu.eflags = pop(SIZE_DWORD);
      }
   }
   else {
      msg("x86emu: Found NULL interrupt handler for int 0x%x at eip = 0x%x, no action taken\n", interrupt_number, saved_eip);
   }
}

void doSysenter() {
   shouldBreak = doBreakOnSyscall;
   switch (os_personality) {
      case PERS_WINDOWS_XP:
         windowsSysenter();
         break;
      case PERS_LINUX_26:
         linuxSysenter();
         break;
      case PERS_CGC_DECREE:
         initiateInterrupt(6, cpu.initial_eip);
         break;
      default:
         msg("sysenter encountered with no defined OS personality\n");
   }
}

//read according to specified n from eip location
unsigned int fetch(unsigned char n) {
//   segmentBase = csBase;
   unsigned int result = readMem(cpu.eip, n);
//   msg("Fetched %d bytes (%x) from %x\n", n, result, cpu.eip); 
   cpu.eip += n;
   return result;
}

//fetch an unsigned quantity
unsigned int fetchu(unsigned char n) {
   return fetch(n) & SIZE_MASKS[n];
}

void fetchOperands16(AddrInfo *dest, AddrInfo *src) {
   unsigned char modrm = fetchu(SIZE_BYTE);
   dest->modrm = modrm;
   unsigned char mod = MOD(modrm);
   unsigned char rm = RM(modrm);
   unsigned int disp = 0;
   if (mod != MOD_3) {
      switch (rm) {
         case 0:
            src->addr = ebx + esi;
            break;
         case 1:
            src->addr = ebx + edi;
            break;
         case 2:
            src->addr = ebp + esi;
            break;
         case 3:
            src->addr = ebp + edi;
            break;
         case 4:
            src->addr = esi;
            break;
         case 5:
            src->addr = edi;
            break;
         case 6:
            src->addr = ebp;
            break;
         case 7:
            src->addr = ebx;
            break;
      }
   }
   src->type = mod == MOD_3 ? TYPE_REG : TYPE_MEM;
   switch (mod) {
      case MOD_0:
         if (rm == 6) {
            src->addr = fetch(SIZE_WORD);
         }
         break;
      case MOD_1:
         disp = (char) fetch(SIZE_BYTE);
         break;
      case MOD_2:
         disp = (int) fetch(SIZE_WORD);
         break;
      case MOD_3:
         src->addr = rm;
         break;
   }
   if (src->type == TYPE_MEM) {
      src->addr += disp;
      src->addr &= SIZE_MASKS[SIZE_WORD];
   }
   dest->addr = REG(modrm);
   dest->type = TYPE_REG;
}

void fetchOperands(AddrInfo *dest, AddrInfo *src) {
   if (prefix & PREFIX_ADDR) {
      fetchOperands16(dest, src);
      return;
   }
   unsigned char modrm = fetchu(SIZE_BYTE);
   dest->modrm = modrm;
   unsigned char mod = MOD(modrm);
   unsigned char rm = RM(modrm);
   unsigned char sib = 0;
   unsigned int disp = 0;
   unsigned char hasSib = 0;
   if (mod != MOD_3) {
      if (rm == 4) {
         sib = fetchu(SIZE_BYTE);
         hasSib = 1;
      }
      else {
         src->addr = cpu.general[rm];
      }
   }
   src->type = mod == MOD_3 ? TYPE_REG : TYPE_MEM;
   switch (mod) {
      case MOD_0:
         if (rm == 5) {
            src->addr = fetch(SIZE_DWORD);
         }
         break;
      case MOD_1:
         disp = (char) fetch(SIZE_BYTE);
         break;
      case MOD_2:
         disp = (int) fetch(SIZE_DWORD);
         break;
      case MOD_3:
         src->addr = rm;
         break;
   }
   if (src->type == TYPE_MEM) {
      src->addr += disp;
      if (hasSib) {
         unsigned int index = INDEX(sib);
         index = index == 4 ? 0 : cpu.general[index] * SCALE(sib);
         src->addr += index;
         unsigned int base = BASE(sib);
         if (base == 5 && mod == MOD_0) {
            src->addr += fetch(SIZE_DWORD);
         }
         else {
            src->addr += cpu.general[base];
         }
      }
   }
   dest->addr = REG(modrm);
   dest->type = TYPE_REG;
}

void A_Ix() {
   dest.addr = 0;
   dest.type = TYPE_REG;
   source.addr = fetch(opsize);
   source.type = TYPE_IMM;
}

void decodeAddressingModes() {
   opsize = opcode & 1 ? opsize : SIZE_BYTE;
   switch (opcode & 0x7) {
      case 0: case 1:
         fetchOperands(&source, &dest);
         break;
      case 2: case 3:
         fetchOperands(&dest, &source);
         break;
      case 4: case 5:
         A_Ix();
         break;
   }
}

//set the segment for data storage and retrieval
// N/A for instruction fetches and stack push/pop
void setSegment() {
   if (prefix & SEG_MASK) {
      int i;
      int seg = PREFIX_CS;
      for (i = 0; i < 6; i++) {
         if (prefix & seg) {
            segmentBase = cpu.segBase[i];
            segmentReg = cpu.segReg[i];
            break;
         }
         seg <<= 1;
      }
   }
   else {  //? Not always the case
      segmentBase = dsBase;
      segmentReg = _ds;
   }
}

unsigned int getOperand(AddrInfo *op) {
   unsigned int mask = SIZE_MASKS[opsize];
   switch (op->type) {
      case TYPE_REG:
         if (opsize == SIZE_BYTE && op->addr >= 4) {
            //AH, CH, DH, BH
            return (cpu.general[op->addr - 4] >> 8) & mask;
         }
         return cpu.general[op->addr] & mask;
      case TYPE_IMM:
         return op->addr & mask;
      case TYPE_MEM:
         setSegment();
         return readMem(op->addr, opsize) & mask;
   }
   return 0;
}

void storeOperand(AddrInfo *op, unsigned int val) {
   unsigned int mask = SIZE_MASKS[opsize];
   val &= mask;
   if (op->type == TYPE_REG) {
      if (opsize == SIZE_BYTE && op->addr >= 4) {
         //AH, CH, DH, BH
         cpu.general[op->addr - 4] &= ~H_MASK;
         cpu.general[op->addr - 4] |= (val << 8);
      }
      else {
         cpu.general[op->addr] &= ~SIZE_MASKS[opsize];
         cpu.general[op->addr] |= val;
      }
   }
   else {
      setSegment();
      writeMem(op->addr, val, opsize);
   }
}

//deal with sign, zero, and parity flags
void setEflags(unsigned long long val, unsigned char size) {
   val &= SIZE_MASKS[size]; //mask off upper bytes
   if (val) CLEAR(xZF);
   else SET(xZF);
   if (val & SIGN_BITS[size]) SET(xSF);
   else CLEAR(xSF);
   if (parityValues[val & 0xFF]) SET(xPF);
   else CLEAR(xPF);
}

//Kris Kaspersky pointed out that the AF flag did not
//function properly for normal adds and subtracts
void checkAuxCarry(unsigned int op1, unsigned int op2, unsigned int result) {
   bool aux = ((op1 ^ op2) & 0x10) != (result & 0x10);
   if (aux) SET(xAF);
   else CLEAR(xAF);
}

bool hasAddOverflow(unsigned int op1, unsigned int op2, unsigned int sum) {
   unsigned int mask = SIGN_BITS[opsize];
   if ((op1 & op2 & ~sum & mask) || (~op1 & ~op2 & sum & mask)) return true;
   else return false;
}

void checkAddOverflow(unsigned int op1, unsigned int op2, unsigned int sum) {
   unsigned int mask = SIGN_BITS[opsize];
   if ((op1 & op2 & ~sum & mask) || (~op1 & ~op2 & sum & mask)) SET(xOF);
   else CLEAR(xOF);
}

unsigned int add(unsigned long long op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned long long result = (op1 & mask) + (op2 & mask);
   if (result & CARRY_BITS[opsize]) SET(xCF);
   else CLEAR(xCF);
   checkAddOverflow((unsigned int)op1, op2, (unsigned int)result);
   setEflags(result, opsize);
   checkAuxCarry((unsigned int)op1, (unsigned int)op2, (unsigned int)result);
   return (unsigned int) result & mask;
}

unsigned int adc(unsigned long long op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned long long result = (op1 & mask) + (op2 & mask) + xC;
   if (result & CARRY_BITS[opsize]) SET(xCF);
   else CLEAR(xCF);
   checkAddOverflow((unsigned int)op1, op2, (unsigned int)result);
   setEflags(result, opsize);
   checkAuxCarry((unsigned int)op1, (unsigned int)op2, (unsigned int)result);
   return (unsigned int) result & mask;
}

bool hasSubOverflow(unsigned int op1, unsigned int op2, unsigned int diff) {
   unsigned int mask = SIGN_BITS[opsize];
   if ((op1 & ~op2 & ~diff & mask) || (~op1 & op2 & diff & mask)) return false;
   else return false;
}

void checkSubOverflow(unsigned int op1, unsigned int op2, unsigned int diff) {
   unsigned int mask = SIGN_BITS[opsize];
   if ((op1 & ~op2 & ~diff & mask) || (~op1 & op2 & diff & mask)) SET(xOF);
   else CLEAR(xOF);
}

unsigned int sub(unsigned long long op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned long long result = (op1 & mask) - (op2 & mask);
   if (result & CARRY_BITS[opsize]) SET(xCF);
   else CLEAR(xCF);
   checkSubOverflow((unsigned int)op1, op2, (unsigned int)result);
   setEflags(result, opsize);
   checkAuxCarry((unsigned int)op1, (unsigned int)op2, (unsigned int)result);
   return (unsigned int) result & mask;
}

unsigned int sbb(unsigned long long op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned long long result = (op1 & mask) - (op2 & mask) - xC;
   if (result & CARRY_BITS[opsize]) SET(xCF);
   else CLEAR(xCF);
   checkSubOverflow((unsigned int)op1, op2, (unsigned int)result);
   setEflags(result, opsize);
   checkAuxCarry((unsigned int)op1, (unsigned int)op2, (unsigned int)result);
   return (unsigned int) result & mask;
}

unsigned int AND(unsigned int op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned int result = (op1 & mask) & (op2 & mask);
   CLEAR(xCF | xOF);
   setEflags(result, opsize);
   return result & mask;
}

unsigned int OR(unsigned int op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned int result = (op1 & mask) | (op2 & mask);
   CLEAR(xCF | xOF);
   setEflags(result, opsize);
   return result & mask;
}

unsigned int XOR(unsigned int op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned int result = (op1 & mask) ^ (op2 & mask);
   CLEAR(xCF | xOF);
   setEflags(result, opsize);
   return result & mask;
}

void cmp(unsigned long long op1, unsigned int op2) {
   unsigned int mask = SIZE_MASKS[opsize];
   unsigned long long result = (op1 & mask) - (op2 & mask);
   if (result & CARRY_BITS[opsize]) SET(xCF);
   else CLEAR(xCF);
   checkSubOverflow((unsigned int)op1, op2, (unsigned int)result);
   setEflags(result, opsize);
}

unsigned int inc(unsigned long long op1) {
   unsigned int oldCarry = xC;
   op1 = add(op1, 1);
   CLEAR(xCF);
   cpu.eflags |= oldCarry;
   return (unsigned int) op1;
}

unsigned int dec(unsigned long long op1) {
   unsigned int oldCarry = xC;
   op1 = sub(op1, 1);
   CLEAR(xCF);
   cpu.eflags |= oldCarry;
   return (unsigned int) op1;
}

void checkLeftOverflow(unsigned int result, unsigned char size) {
   unsigned int msb = result & SIGN_BITS[size];
   if ((msb && xC) || (!msb && xNC)) CLEAR(xOF);
   else SET(xOF);
}

unsigned int rol(unsigned long long op, unsigned char amt) {
   //remove unnecessary rotations
   amt = amt & ROTATE_SIZE_MASKS[opsize];
   if (amt) {
      op = op & SIZE_MASKS[opsize];
      op = (op >> (BITS[opsize] - amt)) | (op << amt);
      if (op & 1) SET(xCF);
      else CLEAR(xCF);
      if (amt == 1) {
         checkLeftOverflow((unsigned int)op, opsize);
      }
   }
   return (unsigned int) op & SIZE_MASKS[opsize];
}

unsigned int ror(unsigned long long op, unsigned char amt) {
   //remove unnecessary rotations
   amt = amt & ROTATE_SIZE_MASKS[opsize];
   if (amt) {
      op = op & SIZE_MASKS[opsize];
      op = (op << (BITS[opsize] - amt)) | (op >> amt);
      if (op & SIGN_BITS[opsize]) SET(xCF);
      else CLEAR(xCF);
      if (amt == 1) {
         unsigned int shift = (unsigned int)op << 1;
         shift = (shift ^ (unsigned int)op) & SIGN_BITS[opsize];
         if (shift) SET(xOF);
         else CLEAR(xOF);
      }
   }
   return (unsigned int) op & SIZE_MASKS[opsize];
}

//probably could do this faster with bit shifts but I am not
//that concerned with speed
unsigned int rcl(unsigned long long op, unsigned char amt) {
   //remove unnecessary rotations
   amt = amt % (ROTATE_SIZE_MASKS[opsize] + 2);
   if (amt) {
      if (xC) op |= CARRY_BITS[opsize];  //setup current carry
      else op &= ~CARRY_BITS[opsize];
      for (int i = amt; i; i--) {
         unsigned long long temp = op & CARRY_BITS[opsize]; //get current carry
         op <<= 1;
         if (temp) op |= 1; //feed carry back in right and
      }
      if (op & CARRY_BITS[opsize]) SET(xCF);  //set final carry
      else CLEAR(xCF);
      if (amt == 1) {
         checkLeftOverflow((unsigned int)op, opsize);
      }
   }
   return (unsigned int) op & SIZE_MASKS[opsize];
}

//probably could do this faster with bit shifts but I am not
//that concerned with speed
unsigned int rcr(unsigned long long op, unsigned char amt) {
   int temp = xC; //get initial carry
   //remove unnecessary rotations
   amt = amt % (ROTATE_SIZE_MASKS[opsize] + 2);
   if (amt) {
      if (amt == 1) {
         checkLeftOverflow((unsigned int)op, opsize);
      }
      for (int i = amt; i; i--) {
         if (temp) op |= CARRY_BITS[opsize];  //prepare to feed carry in from left
         else op &= ~CARRY_BITS[opsize];
         temp = (int)op & 1; //get next carry
         op >>= 1;
      }
      if (temp) SET(xCF);  //set final carry
      else CLEAR(xCF);
   }
   return (unsigned int) op & SIZE_MASKS[opsize];
}

unsigned int shl(unsigned long long op, unsigned char amt) {
   if (amt) {
      op <<= amt;
      if (op & CARRY_BITS[opsize]) SET(xCF);
      else CLEAR(xCF);
      if (amt == 1) {
         checkLeftOverflow((unsigned int)op, opsize);
      }
      setEflags(op, opsize);  //flags only affected when amt != 0
   }
   return (unsigned int) op & SIZE_MASKS[opsize];
}

//mask op down to size before calling
unsigned int shiftRight(unsigned long long op, unsigned char amt) {
   if (amt) {
      unsigned int final_carry = 1 << (amt - 1);
      if (op & final_carry) SET(xCF);
      else CLEAR(xCF);
      op >>= amt;
      setEflags(op, opsize);  //flags only affected when amt != 0
   }
   return (unsigned int) op;
}

unsigned int shr(unsigned long long op, unsigned char amt) {
   if (amt == 1) {
      if (op & SIGN_BITS[opsize]) SET(xOF);
      else CLEAR(xOF);
   }
   return shiftRight(op & SIZE_MASKS[opsize], amt);
}

unsigned int sar(unsigned long long op, unsigned char amt) {
   op = op & SIZE_MASKS[opsize];
   switch (opsize) {
      case SIZE_BYTE:
         op = sedq(sebd((unsigned char)op));
         break;
      case SIZE_WORD:
         op = sedq(sewd((unsigned short)op));
         break;
      case SIZE_DWORD:
         op = sedq((unsigned int)op);
         break;
   }
   if (amt == 1) {
      CLEAR(xOF);
   }
   return shiftRight(op, amt);
}

unsigned int shrd(unsigned long long op1, unsigned long long bits, unsigned char amt) {
   if (amt) {
      unsigned int newCarry = 1 << (amt - 1);
      if (op1 & newCarry) SET(xCF);
      else CLEAR(xCF);
      bits <<= (BITS[opsize] - amt);
      op1 = ((op1 & SIZE_MASKS[opsize]) >> amt) | bits;
      setEflags(op1, opsize);
   }
   return (unsigned int) (op1 & SIZE_MASKS[opsize]);
}

unsigned int shld(unsigned long long op1, unsigned long long bits, unsigned char amt) {
   if (amt) {
      unsigned int newCarry = 1 << (BITS[opsize] - amt);
      if (op1 & newCarry) SET(xCF);
      else CLEAR(xCF);
      bits = (bits & SIZE_MASKS[opsize]) >> (BITS[opsize] - amt);
      op1 = (op1 << amt) | bits;
      setEflags(op1, opsize);
   }
   return (unsigned int) (op1 & SIZE_MASKS[opsize]);
}

void dShift() {
   fetchOperands(&source, &dest);
   unsigned char amt;
   if ((opcode & 7) == 4) {
      amt = fetch(SIZE_BYTE);
   }
   else {
      amt = ecx & 0xFF;
   }
   amt &= 0x1F;
   unsigned int result;
   unsigned int op1 = getOperand(&dest);
   unsigned int op2 = getOperand(&source);
   if (opcode < 0xA8) {
      result = shld(op1, op2, amt);
   }
   else {
      result = shrd(op1, op2, amt);
   }
   storeOperand(&dest, result);
}

unsigned int getLongShiftCount(AddrInfo *dest, AddrInfo *source) {
   ll_union shift, s2;
   s2.ll = 0;
   if (source->type == TYPE_REG) {
      if (prefix & PREFIX_SIZE) {
         shift.ll = sse2.xmm.ll[source->addr][0];
         s2.ll = sse2.xmm.ll[source->addr][1];
      }
      else {
         shift.ll = fpu.r[dest->addr].ll;
      }
   }
   else {
      shift.low = (unsigned int)readMem(source->addr, SIZE_DWORD);
      shift.high = (unsigned int)readMem(source->addr + 4, SIZE_DWORD);
      if (prefix & PREFIX_SIZE) {
         s2.low = (unsigned int)readMem(source->addr + 8, SIZE_DWORD);
         s2.high = (unsigned int)readMem(source->addr + 12, SIZE_DWORD);
      }
   }
   if (shift.ll > 256 || s2.ll != 0) {
      return 256;   //exceeds any legal shift count
   }
   else {
      return shift.low;
   }
}

void doCall(unsigned int addr) {
#ifdef __IDP__
   hookfunc hook = findHookedFunc(addr);
//   hookfunc hook = findHook(instStart);
   if (hook) {
      (*hook)(addr);
   }
   else if (isModuleAddress(addr)) {
      //this function is in a loaded module
      char *name = reverseLookupExport(addr);
      if (name) {
         (*checkForHook(name, addr, 0))(addr);
      }
      else {
         msg("x86emu: call to dll function that is not exported %X\n", addr);
         shouldBreak = 1;
      }
   }
   else {
#endif
      push(cpu.eip, SIZE_DWORD);
      cpu.eip = addr;
#ifdef __IDP__
   }
#endif
}

int checkJumpFunction(unsigned int addr) {
#ifdef __IDP__
   if (findHookedFunc(addr) || isModuleAddress(addr)) {
      // get the return address into eip
      cpu.eip = pop(SIZE_DWORD);
      doCall(addr);
      return 1;
   }
#endif
   return 0;
}

//handle instructions that begin w/ 0x0n
int doZero() {
   unsigned char op = opcode & 0x0F;
   unsigned int result;
   if ((op & 0x7) < 6) {
      decodeAddressingModes();
      unsigned int op1 = getOperand(&dest);
      unsigned int op2 = getOperand(&source);
      if (op < 8) { // ADD
         result = add(op1, op2);
      }
      else { // OR
         result = OR(op1, op2);
      }
      storeOperand(&dest, result);
   }
   else {
      switch (op) {
         case 0x06:
            push(_es, SIZE_WORD);
            break;
         case 0x07:
            _es = pop(SIZE_WORD);
            break;
         case 0x0E:
            push(_cs, SIZE_WORD);
            break;
         case 0x0F:
            return doEscape();
      }
   }
   return 1;
}

//handle instructions that begin w/ 0x1n
int doOne() {
   unsigned char op = opcode & 0x0F;
   unsigned int result;
   if ((op & 0x7) < 6) {
      decodeAddressingModes();
      unsigned int op1 = getOperand(&dest);
      unsigned int op2 = getOperand(&source);
      if (op < 8) { // ADC
         result = adc(op1, op2);
      }
      else { // SBB
         result = sbb(op1, op2);
      }
      storeOperand(&dest, result);
   }
   else {
      switch (op) {
         case 6:
            push(_ss, SIZE_WORD);
            break;
         case 7:
            _ss = pop(SIZE_WORD);
            break;
         case 0xE:
            push(_ds, SIZE_WORD);
            break;
         case 0xF:
            _ds = pop(SIZE_WORD);
            break;
      }
   }
   return 1;
}

//handle instructions that begin w/ 0x2n
int doTwo() {
   unsigned char op = opcode & 0x0F;
   unsigned int result;
   if ((op & 0x7) < 6) {
      decodeAddressingModes();
      unsigned int op1 = getOperand(&dest);
      unsigned int op2 = getOperand(&source);
      if (op < 8) { // AND
         result = AND(op1, op2);
      }
      else { // SUB
         result = sub(op1, op2);
      }
      storeOperand(&dest, result);
   }
   else {
      switch (op) {
         case 0x6:
            prefix |= PREFIX_ES;
            return 0;
         case 7: { //DAA
            unsigned int al = eax & 0xFF;
            if (((al & 0x0F) > 9) || (cpu.eflags & xAF)) {
               unsigned int old_al = al;
               SET(xAF);
               al += 6;
               if (xC || ((al ^ old_al) & 0x10)) SET(xCF);
            }
            else {
               CLEAR(xAF);
            }
            if (((al & 0xF0) > 0x90) || xC) {
               al += 0x60;
               SET(xCF);
            }
            else {
               CLEAR(xCF);
            }
            eax = (eax & 0xFFFFFF00) | (al & 0xFF);
            setEflags(eax, SIZE_BYTE);
            break;
         }
         case 0xE:
            prefix |= PREFIX_CS;
            return 0;
         case 0xF: { //DAS
            unsigned int al = eax & 0xFF;
            if (((al & 0x0F) > 9) || (cpu.eflags & xAF)) {
               unsigned int old_al = al;
               SET(xAF);
               al -= 6;
               if (xC || ((al ^ old_al) & 0x10)) SET(xCF);
            }
            else {
               CLEAR(xAF);
            }
            if (((al & 0xFF) > 0x9F) || xC) {
               al -= 0x60;
               SET(xCF);
            }
            else {
               CLEAR(xCF);
            }
            eax = (eax & 0xFFFFFF00) | (al & 0xFF);
            setEflags(eax, SIZE_BYTE);
            break;
         }
      }
   }
   return 1;
}

//handle instructions that begin w/ 0x3n
int doThree() {
   unsigned char op = opcode & 0x0F;
   if ((op & 0x7) < 6) {
      decodeAddressingModes();
      unsigned int op1 = getOperand(&dest);
      unsigned int op2 = getOperand(&source);
      if (op < 8) { // XOR
         storeOperand(&dest, XOR(op1, op2));
      }
      else { // CMP
         cmp(op1, op2);
      }
   }
   else {
      switch (op) {
         case 0x6:
            prefix |= PREFIX_SS;
            return 0;
         case 7: {//AAA
            unsigned int al = eax & 0xFF;
            unsigned int ax = eax & 0xFF00;
            if (((al & 0x0F) > 9) || (cpu.eflags & xAF)) {
               SET(xCF | xAF);
               ax += 0x100;
               al += 6;
            }
            else {
               CLEAR(xCF | xAF);
            }
            ax |= al;
            eax = (eax & 0xFFFF0000) | (ax & 0xFF0F);
            break;
         }
         case 0xE:
            prefix |= PREFIX_DS;
            return 0;
         case 0xF: {//AAS
            unsigned int al = eax & 0xFF;
            unsigned int ax = eax & 0xFF00;
            if (((al & 0x0F) > 9) || (cpu.eflags & xAF)) {
               SET(xCF | xAF);
               ax = (ax - 0x100) & 0xFF00;
               al -= 6;
            }
            else {
               CLEAR(xCF | xAF);
            }
            ax |= al;
            eax = (eax & 0xFFFF0000) | (ax & 0xFF0F);
            break;
         }
      }
   }
   return 1;
}

//handle instructions that begin w/ 0x4n
int doFour() {
   unsigned char op = opcode & 0x0F;
   unsigned char reg = op & 7;
   unsigned int mask = SIZE_MASKS[opsize];
   //skip source setup, just read the register
   unsigned int result = cpu.general[reg] & mask;
   dest.type = TYPE_REG;
   dest.addr = reg;
   if (op < 8) { // INC
      result = inc(result);
   }
   else { // DEC
      result = dec(result);
   }
   storeOperand(&dest, result);
   setEflags(result, opsize);
   return 1;
}

//handle instructions that begin w/ 0x5n
int doFive() {
   unsigned char op = opcode & 0x0F;
   unsigned char reg = op & 7;
   //skip source setup, just setup the destination
   dest.type = TYPE_REG;
   dest.addr = reg;
   if (op < 8) { // PUSH
      push(cpu.general[reg], opsize);
   }
   else { // POP
      storeOperand(&dest, pop(opsize));
   }
   return 1;
}

void stepd(unsigned char size) {
   xD ? (edi -= size) : (edi += size);
}

void steps(unsigned char size) {
   xD ? (esi -= size) : (esi += size);
}

void step(unsigned char size) {
   stepd(size);
   steps(size);
}

//handle instructions that begin w/ 0x6n
int doSix() {
   unsigned char op = opcode & 0x0F;
   unsigned int result = 0;
   int op1, op2;
   unsigned int rep = prefix & PREFIX_REP;
   //skip source setup, just setup the destination
   dest.type = TYPE_REG;
   switch (op) {
      case 0: //PUSHA/PUSHAD
         result = esp;
         for (source.addr = EAX; source.addr <= EDI; source.addr++) {
            if (source.addr != ESP) push(cpu.general[source.addr], opsize);
            else push(result, opsize);
         }
         break;
      case 1: {//POPA/POPAD
         for (int j = EDI; j >= EAX; j--) { //need signed number for this test
            dest.addr = (unsigned int)j;
            if (dest.addr == ESP) pop(opsize);
            else storeOperand(&dest, pop(opsize));
         }
         break;
      }
      case 2: //BOUND
         break;
      case 3: //ARPL
         break;
      case 0x4:
         prefix |= PREFIX_FS;
         return 0;
      case 0x5:
         prefix |= PREFIX_GS;
         return 0;
      case 0x6:
         prefix |= PREFIX_SIZE;
         opsize = SIZE_WORD;
         return 0;
      case 0x7:
         prefix |= PREFIX_ADDR;
         return 0;
      case 8: //PUSH Iv
         push(fetch(opsize), opsize);
         break;
      case 9: //IMUL Iv
         fetchOperands(&dest, &source);
         op1 = getOperand(&source);
         op2 = fetch(opsize);  //need to do some size alignment here
         result = op1 * op2;
         storeOperand(&dest, result);
         setEflags(result, opsize);
         break;
      case 0xA: //PUSH Ib
         //not certain this should be sign extended
         push(sebd(fetch(SIZE_BYTE)), opsize);
         break;
      case 0xB: //IMUL Ib
         fetchOperands(&dest, &source);
         op1 = getOperand(&source);
         op2 = fetch(SIZE_BYTE); //need to do some size alignement here
         result = op1 * op2;
         storeOperand(&dest, result);
         setEflags(result, SIZE_BYTE);
         break;
      case 0xC: //INS
         opsize = SIZE_BYTE;
      case 0xD: //INS
         segmentBase = esBase;
         segmentReg = _es;
         if (rep) {
            while (ecx) {
//               writeMem(edi, eax, opsize);  //we are not really going to write data
               stepd(opsize);
               ecx--;        //FAILS to take addr size into account
            }
         }
         else {
//            writeMem(edi, eax, opsize);  //we are not really going to write data
            stepd(opsize);
         }
         break;
      case 0xE: //OUTS
         opsize = SIZE_BYTE;
      case 0xF: //OUTS
         source.type = TYPE_MEM;
         if (rep) {
            while (ecx) {
               //we will read the data but not do anything with it
               source.addr = esi;
               getOperand(&source);
               steps(opsize);
               ecx--;        //FAILS to take addr size into account
            }
         }
         else {
            //we will read the data but not do anything with it
            source.addr = esi;
            getOperand(&source);
            steps(opsize);
         }
         break;
   }
   return 1;
}

//handle instructions that begin w/ 0x7n
int doSeven() {
   unsigned char op = opcode & 0x0F;
   unsigned int imm = fetch(opsize);
   int branch = 0;
   switch (op) {
      case 0: //JO
         branch = xO;
         break;
      case 1: //JNO
         branch = xNO;
         break;
      case 2: //B/NAE/C
         branch = xB;
         break;
      case 3: //NB/AE/NC
         branch = xNB;
         break;
      case 4:  //E/Z
         branch = xZ;
         break;
      case 5:  //NE/NZ
         branch = xNZ;
         break;
      case 6:  //BE/NA
         branch = xBE;
         break;
      case 7:  //NBE/A
         branch = xA;
         break;
      case 8: //S
         branch = xS;
         break;
      case 9: //NS
         branch = xNS;
         break;
      case 0xA: //P/PE
         branch = xP;
         break;
      case 0xB: //NP/PO
         branch = xNP;
         break;
      case 0xC: //L/NGE
         branch = xL;
         break;
      case 0xD: //NL/GE
         branch = xGE;
         break;
      case 0xE: //LE/NG
         branch = xLE;
         break;
      case 0xF: //NLE/G
         branch = xG;
         break;
   }
   if (branch) {
      cpu.eip += (opsize == SIZE_BYTE) ? sebd(imm) : imm;
   }
   return 1;
}

//handle instructions that begin w/ 0x8n
int doEight() {
   unsigned char op = opcode & 0x0F;
   unsigned int op1, op2;
   unsigned char size = op & 1 ? opsize : SIZE_BYTE;
   switch (op) {
   case 0: case 1: case 2: case 3: {
         //83 is sign extended unsigned char->unsigned int
         //is 82 ever actually used?
         unsigned char subop;
         opsize = size;
         fetchOperands(&source, &dest); //we will ignore Gx info
         subop = (unsigned char) source.addr;
         op2 = fetch((op == 1) ? opsize : SIZE_BYTE);
         if (op == 3) op2 = sebd(op2);
         op1 = getOperand(&dest);
         //ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
         switch (subop) {
            case 0: //ADD
               storeOperand(&dest, add(op1, op2));
               break;
            case 1: //OR
               storeOperand(&dest, OR(op1, op2));
               break;
            case 2: //ADC
               storeOperand(&dest, adc(op1, op2));
               break;
            case 3: //SBB
               storeOperand(&dest, sbb(op1, op2));
               break;
            case 4: //AND
               storeOperand(&dest, AND(op1, op2));
               break;
            case 5: //SUB
               storeOperand(&dest, sub(op1, op2));
               break;
            case 6: //XOR
               storeOperand(&dest, XOR(op1, op2));
               break;
            case 7: //CMP
               cmp(op1, op2);
               break;
         }
      }
      break;
   case 4: case 5: case 6: case 7:
      opsize = size;
      fetchOperands(&source, &dest);
      if (op < 6) { //TEST
         AND(getOperand(&source), getOperand(&dest));
      }
      else { //XCHG
         unsigned int temp = getOperand(&dest);
         storeOperand(&dest, getOperand(&source));
         storeOperand(&source, temp);
      }
      break;
   case 8: case 9: case 0xA: case 0xB:   //MOV
      opsize = size;
      decodeAddressingModes();
      storeOperand(&dest, getOperand(&source));
      break;
   case 0xC: //MOV reg seg
      fetchOperands(&source, &dest); //generate the address
      storeOperand(&dest, cpu.segReg[seg3_map[source.addr]]); //store the address
      break;
   case 0xD: //LEA
      fetchOperands(&dest, &source); //generate the address
      storeOperand(&dest, source.addr); //store the address
      break;
   case 0xE: { //MOV seg reg
      fetchOperands(&dest, &source); //generate the address
      //should generate invalid opcode #UD here if dest == CS
      //need to load segment shadow base from GDT/LDT
      unsigned int segReg = seg3_map[dest.addr];
      unsigned short newSeg = (unsigned short)cpu.general[source.addr];
      cpu.segReg[segReg] = newSeg;
      if (newSeg & 4) {
         //LDT descriptor
      }
      else {
         //GDT descriptor
         cpu.segBase[segReg] = getGdtDescBase(newSeg >> 3);
      }
      break;
   }
   case 0xF: {//POP
         unsigned int val = pop(opsize);
         fetchOperands(&source, &dest); //no source, just generate destination info
         storeOperand(&dest, val);
      }
      break;
   }
   return 1;
}

//handle instructions that begin w/ 0x9n
int doNine() {
   unsigned char op = opcode & 0x0F;
   unsigned int temp;
   dest.type = TYPE_REG;
   if (op < 8) { //0 is actually NOP, but we do XCHG eax, eax here
      dest.addr = op & 7;
      temp = cpu.general[dest.addr];
      storeOperand(&dest, eax);
      dest.addr = 0;
      storeOperand(&dest, temp);
   }
   else {
      switch (op) {
         case 8: //CBW/CWDE
            dest.addr = EAX;
            if (opsize == SIZE_WORD) storeOperand(&dest, sebw(eax));
            else storeOperand(&dest, sewd(eax));
            break;
         case 9: //CWD/CDQ
            dest.addr = EDX;
            temp = eax & SIGN_BITS[opsize] ? 0xFFFFFFFF : 0;
            storeOperand(&dest, temp);
            break;
         case 0xA: //CALLF  //not required for my purposes?
            break;
         case 0xB: //FWAIT/WAIT  //not dealing with FP
            break;
         case 0xC: //PUSHF/PUSHFD
            push(cpu.eflags, opsize);
            break;
         case 0xD: //POPF/POPFD
            //don't allow changing flags at higher privilege levels
            cpu.eflags = (cpu.eflags & ~current_priv_flags) | (pop(opsize) & current_priv_flags);
            break;
         case 0xE: //SAHF
            temp = eax >> 8;
            temp &= 0xD5;
            temp |= 2;
            cpu.eflags &= ~SIZE_MASKS[SIZE_BYTE];
            cpu.eflags |= temp;
            break;
         case 0xF: //LAHF
            temp = (cpu.eflags & SIZE_MASKS[SIZE_BYTE]) << 8;
            eax &= ~H_MASK;
            eax |= temp;
            break;
      }
   }
   return 1;
}

//handle instructions that begin w/ 0xAn
int doTen() {
   unsigned char op = opcode & 0x0F;
   unsigned int data;
   unsigned int rep = prefix & PREFIX_REP;
   unsigned int repne = prefix & PREFIX_REPNE;
   unsigned int loop = prefix & (PREFIX_REP | PREFIX_REPNE);
   unsigned int override = prefix & PREFIX_ADDR;
   dest.addr = EAX;
   dest.type = TYPE_REG;
   switch (op) {
      case 0: // Segemented MOV moffs
         opsize = SIZE_BYTE;
         //break; // !! Should Not break. - NOTE error by daineng 20050704
      case 1: // Segemented MOV moffs
         source.addr = fetch(override ? SIZE_WORD : SIZE_DWORD);
         source.type = TYPE_MEM;
         storeOperand(&dest, getOperand(&source));
         break;
      case 2: // Segemented MOV moffs
         opsize = SIZE_BYTE;
         //break; // related to above error
      case 3: // Segemented MOV moffs
         dest.addr = fetch(override ? SIZE_WORD : SIZE_DWORD);
         dest.type = TYPE_MEM;
         storeOperand(&dest, eax);
         break;
      case 4:  //MOVS/MOVSB
         opsize = SIZE_BYTE;
      case 5:  //MOVS/MOVSW/MOVSD
         source.type = TYPE_MEM;
         if (rep) {
            while (ecx) {
               source.addr = esi;
               unsigned int val = getOperand(&source);
               segmentBase = esBase;
               segmentReg = _es;
               writeMem(edi, val, opsize);
               step(opsize);
               ecx--;        //FAILS to take addr size into account
            }
         }
         else {
            source.addr = esi;
            unsigned int val = getOperand(&source);
            segmentBase = esBase;
            segmentReg = _es;
            writeMem(edi, val, opsize);
            step(opsize);
         }
         break;
      case 6:  //CMPS/CMPSB
         opsize = SIZE_BYTE;
      case 7: //CMPS/CMPSW/CMPSD
         source.type = TYPE_MEM;
         if (loop) {
            while (ecx) {
               source.addr = esi;
               unsigned int val = getOperand(&source);
               segmentBase = esBase;
               segmentReg = _es;
               cmp(val, readMem(edi, opsize));
               step(opsize);
               ecx--;        //FAILS to take addr size into account
               if (rep && xNZ) break;
               if (repne && xZ) break;
            }
         }
         else {
            source.addr = esi;
            unsigned int val = getOperand(&source);
            segmentBase = esBase;
            segmentReg = _es;
            cmp(val, readMem(edi, opsize));
            step(opsize);
         }
         break;
      case 8: case 9: //TEST
         if (op == 8) {
            opsize = SIZE_BYTE;
         }
         data = fetch(opsize);
         AND(getOperand(&dest), data);
         break;
      case 0xA: //STOS/STOSB
         opsize = SIZE_BYTE;
      case 0xB: //STOS/STOSW/STOSD
         segmentBase = esBase;
         segmentReg = _es;
         if (rep) {
            while (ecx) {
               writeMem(edi, eax, opsize);
               stepd(opsize);
               ecx--;        //FAILS to take addr size into account
            }
         }
         else {
            writeMem(edi, eax, opsize);
            stepd(opsize);
         }
         break;
      case 0xC: //LODS/LODSB
         opsize = SIZE_BYTE;
      case 0xD: //LODS/LODSW/LODSD
         source.type = TYPE_MEM;
         if (rep) {
            while (ecx) {
               source.addr = esi;
               unsigned int val = getOperand(&source);
               eax &= ~SIZE_MASKS[opsize];
               eax |= val;
               steps(opsize);
               ecx--;        //FAILS to take addr size into account
            }
         }
         else {
            source.addr = esi;
            unsigned int val = getOperand(&source);
            eax &= ~SIZE_MASKS[opsize];
            eax |= val;
            steps(opsize);
         }
         break;
      case 0xE: //SCAS/SCASB
         opsize = SIZE_BYTE;
      case 0xF: //SCAS/SCASW/SCASD
         segmentBase = esBase;
         segmentReg = _es;
         if (loop) {
            while (ecx) {
               cmp(eax, readMem(edi, opsize));
               stepd(opsize);
               ecx--;        //FAILS to take addr size into account
               if (rep && xNZ) break;
               if (repne && xZ) break;
            }
         }
         else {
            cmp(eax, readMem(edi, opsize));
            stepd(opsize);
         }
         break;
   }
   return 1;
}

//handle instructions that begin w/ 0xBn
int doEleven() {
   unsigned char op = opcode & 0x0F;
   dest.addr = op & 7;
   dest.type = TYPE_REG;
   if (op < 8) {
      unsigned int data = fetch(SIZE_BYTE);
      if (op < 4) {
         opsize = SIZE_BYTE;
         storeOperand(&dest, data);
      }
      else {
         cpu.general[dest.addr & 3] &= ~H_MASK;
         data <<= 8;
         cpu.general[dest.addr & 3] |= (data & H_MASK);
      }
   }
   else {
      storeOperand(&dest, fetch(opsize));
   }
   return 1;
}

//handle instructions that begin w/ 0xCn
int doTwelve() {
   unsigned char op = opcode & 0x0F;
   unsigned char subop;
   unsigned int delta, temp;
   switch (op) {
      case 0: //
         opsize = SIZE_BYTE;
      case 1: // SHFT Group 2
         fetchOperands(&source, &dest);
         subop = source.addr;
         delta = fetch(SIZE_BYTE) & 0x1F;  //shift amount
         if (delta) {
            temp = getOperand(&dest);
            switch (subop) {
               case 0: //ROL
                  storeOperand(&dest, rol(temp, delta));
                  break;
               case 1: //ROR
                  storeOperand(&dest, ror(temp, delta));
                  break;
               case 2: //RCL
                  storeOperand(&dest, rcl(temp, delta));
                  break;
               case 3: //RCR
                  storeOperand(&dest, rcr(temp, delta));
                  break;
               case 4:  //SHL/SAL
                  storeOperand(&dest, shl(temp, delta));
                  break;
               case 5:  //SHR
                  storeOperand(&dest, shr(temp, delta));
                  break;
               case 7: //SAR
                  storeOperand(&dest, sar(temp, delta));
                  break;
            }
         }
         break;
      case 2: //RETN Iw
         delta = fetchu(SIZE_WORD);
         cpu.eip = pop(SIZE_DWORD);
         esp += delta;
         if (cpu.eip == SEH_MAGIC) {
            sehReturn();
         }
         else if (cpu.eip == VEH_MAGIC) {
            vehReturn();
         }
         else if (cpu.eip == THREAD_MAGIC) {
            //need to destroy thread and choose new active thread
            emu_switch_threads(emu_destroy_thread(activeThread->handle));
         }
         break;
      case 3: //RETN
         cpu.eip = pop(SIZE_DWORD);
         if (cpu.eip == SEH_MAGIC) {
            sehReturn();
         }
         else if (cpu.eip == VEH_MAGIC) {
            vehReturn();
         }
         else if (cpu.eip == THREAD_MAGIC) {
            //need to destroy thread and choose new active thread
            emu_switch_threads(emu_destroy_thread(activeThread->handle));
         }
         break;
      case 4:  //LES - NOT using segments now
         break;
      case 5:  //LDS - NOT using segments now
         break;
      case 6:  // MOV
         opsize = SIZE_BYTE;
      case 7: // MOV
         fetchOperands(&source, &dest);
         storeOperand(&dest, fetch(opsize));
         break;
      case 8: //ENTER
         delta = fetchu(SIZE_WORD);
         subop = fetchu(SIZE_BYTE);
         push(ebp, SIZE_DWORD);
         temp = esp;
         if (subop > 0) {
            while (--subop) {
               ebp -= 4;
               push(readMem(ebp, SIZE_DWORD), SIZE_DWORD);
            }
            push(temp, SIZE_DWORD);
         }
         ebp = temp;
         esp -= delta;
         break;
      case 9: //LEAVE
         esp = ebp;
         ebp = pop(SIZE_DWORD);
         break;
      case 0xA: //RETF Iw
         break;
      case 0xB: //RETF
         break;
      case 0xC: case 0xD: case 0xE: //INT 3 = 0xCC, INT Ib, INTO
         if (op == 0xD) subop = fetchu(SIZE_BYTE);  //this is the interrupt vector
         else subop = op == 0xC ? 3 : 4;  //3 == TRAP, 4 = O
         msg("%02x %02x at 0x%x\n", opcode, subop, cpu.eip);
         initiateInterrupt(subop, cpu.eip);
         break;
      case 0xF: //IRET
         doInterruptReturn();
         break;
   }
   return 1;
}

//handle instructions that begin w/ 0xDn
int doThirteen() {
   unsigned char op = opcode & 0x0F;
   unsigned char subop = 0;
   unsigned int delta, temp;
   float *fp32 = NULL;
   double *fp64 = NULL;
   long double *fp80 = NULL;
   short *i16 = NULL;
   unsigned long long *i64 = NULL;
   int i32[3];
   long double dbl;
   if (op > 7) {
      fetchOperands(&dest, &source);
      subop = dest.addr;
      //if source.type == TYPE_REG  ==> modrm >= 0xC0
      //   modrm == 0xC0 | (dest.addr << 3) | source.addr
      //else
      //   dest.addr is the subop
      //   and source.addr is the address of the operand
      fp32 = (float*)i32;
      fp64 = (double*)i32;
      fp80 = (long double*)i32;
      i16 = (short*)i32;
      i64 = (unsigned long long*)i32;
   }
   switch (op) {
      case 0: case 2: //
         opsize = SIZE_BYTE;
      case 1: case 3: // SHFT Group 2
         fetchOperands(&source, &dest);
         subop = source.addr;
         delta = op < 2 ? 1 : ecx & 0x1F;  //shift amount
         temp = getOperand(&dest);
         switch (subop) {
            case 0: //ROL
               storeOperand(&dest, rol(temp, delta));
               break;
            case 1: //ROR
               storeOperand(&dest, ror(temp, delta));
               break;
            case 2: //RCL
               storeOperand(&dest, rcl(temp, delta));
               break;
            case 3: //RCR
               storeOperand(&dest, rcr(temp, delta));
               break;
            case 4:  //SHL/SAL
               storeOperand(&dest, shl(temp, delta));
               break;
            case 5:  //SHR
               storeOperand(&dest, shr(temp, delta));
               break;
            case 7: //SAR
               storeOperand(&dest, sar(temp, delta));
               break;
         }
         break;
      case 4: case 5: {//AAM / AAD
         unsigned int base = fetchu(SIZE_BYTE);
         unsigned int al = eax & 0xFF;
         unsigned int ah = (eax >> 8) & 0xFF;
         unsigned int ax = (op == 4) ? ((al / base) << 8) | (al % base) :
                                (al + ah * base) & 0xFF;
         setEflags(ax, SIZE_WORD);
         eax = (eax & ~SIZE_MASKS[SIZE_WORD]) | ax;
         break;
      }
      case 6: //undocumented SALC
         eax = eax & ~SIZE_MASKS[SIZE_BYTE];
         if (xC) eax |= 0xFF;
         break;
      case 7: //XLAT/XLATB
         break;
      case 8: //
         if (source.type != TYPE_REG) {
            //source.addr is float*
            i32[0] = readMem(source.addr, SIZE_DWORD);
            switch (subop) {
               case 0:    //FADD
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = *fp32 + fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 1:    //FMUL
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = *fp32 * fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 2:    //FCOM
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  fpuCompare(fpuGet(0), *fp32);
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 3:    //FCOMP
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  dbl = fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuCompare(dbl, *fp32);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 4:    //FSUB
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = fpuPop() - *fp32;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 5:    //FSUBR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = *fp32 - fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 6:    //FDIV
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = fpuPop() / *fp32;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 7:    //FDIVR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = *fp32 /fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {            //FADD ST(0), ST(i)
                     *fp80 = fpuPop() + *fp80;
                  }
                  else {                      //FMUL ST(0), ST(i)
                     *fp80 = fpuPop() * *fp80;
                  }
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(0, 0xD8C0 + lower);
                  break;
               case 0xD0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {            //FCOM ST(0), ST(i)
                     fpuCompare(fpuGet(0), *fp80);
                  }
                  else {                      //FCOMP ST(0), ST(i)
                     dbl = fpuPop();
                     if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                        fpuCompare(dbl, *fp80);
                     }
                  }
                  fpuSetPointers(0, 0xD8D0 + lower);
                  break;
               case 0xE0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {            //FSUB ST(0) / ST(i)
                     *fp80 = fpuPop() - *fp80;
                  }
                  else {            //FSUBR ST(0) / ST(i)
                     *fp80 = *fp80 - fpuPop();
                  }
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(0, 0xD8E0 + lower);
                  break;
               case 0xF0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {            //FDIV ST(0) / ST(i)
                     *fp80 = fpuPop() / *fp80;
                  }
                  else {         //FDIVR ST(0) / ST(i)
                     *fp80 = *fp80 / fpuPop();
                  }
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(0, 0xD8F0 + lower);
                  break;
            }
         }
         break;
      case 9: //
         if (source.type != TYPE_REG) {
            switch (subop) {
               case 0:    //FLD
                  //source.addr is float*
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  fpuPush(*fp32);
                  fpuSetPointers(source.addr, 0xD900 | dest.modrm);
                  break;
               case 1:    //should not happen
                  break;
               case 2:    //FST
                  //source.addr is float*
                  *fp32 = (float)fpuGet(0);
                  writeMem(source.addr, i32[0], SIZE_DWORD);
                  fpuSetPointers(source.addr, 0xD900 | dest.modrm);
                  break;
               case 3:    //FSTP
                  //source.addr is float*
                  *fp32 = (float)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xD900 | dest.modrm);
                  break;
               case 4:    //FLDENV
                  fpuLoadEnv(source.addr);
                  break;
               case 5:    //FLDCW
                  fpu.control = (short)readMem(source.addr, SIZE_WORD);
                  fpuSetPointers(source.addr, 0xD900 | dest.modrm);
                  break;
               case 6: {   //FNSTENV
                  fpuStoreEnv(source.addr);
                  break;
               }
               case 7:    //FSTCW
                  opsize = SIZE_WORD;
                  storeOperand(&source, fpu.control);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:
                  if (lower >= 8) {    //FXCH
                     long double st0 = fpuGet(0);
                     long double sti = fpuGet(lower & 7);
                     fpuSet(0, sti);
                     fpuSet(lower & 7, st0);
                     fpuSetPointers(0, 0xD900 | dest.modrm);
                  }
                  else { //FLD
                     //*** need implementaiton 
                     fpuSetPointers(0, 0xD900 | dest.modrm);
                  }
                  break;
               case 0xD0:  //D0 is fnop, D1-DF are undefined
                  if (lower == 0) {  //FNOP
                     fpuSetPointers(0, 0xD900 | dest.modrm);
                  }
                  break;
               case 0xE0:
                  switch (lower) {
                     case 0x0:   //FCHS
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           //if we are masking IE or there is no stack fault
                           //then complete the operation
                           fpuPush(fabs(-(*fp80)));
                        }
                        fpuSetPointers(0, 0xD9E0);
                        break;
                     case 0x1:   //FABS
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(fabs(*fp80));
                        }
                        fpuSetPointers(0, 0xD9E1);
                        break;
                     case 0x4:
                        fpuCompare(fpuGet(0), 0);
                        fpuSetPointers(source.addr, 0xD9E4);
                        break;
                     case 0x8:   //FLD1
                        fpuPush(1.0);
                        fpuSetPointers(0, 0xD9E8);
                        break;
                     case 0x9:   //FLDL2T
                        fpuPush(M_LN10 / M_LN2);
                        fpuSetPointers(0, 0xD9E9);
                        break;
                     case 0xA:   //FLDL2E
                        fpuPush(M_LOG2E);
                        fpuSetPointers(0, 0xD9EA);
                        break;
                     case 0xB:   //FLDPI
                        fpuPush(M_PI);
                        fpuSetPointers(0, 0xD9EB);
                        break;
                     case 0xC:   //FLDLG2
                        fpuPush(M_LN2 / M_LN10);
                        fpuSetPointers(0, 0xD9EC);
                        break;
                     case 0xD:   //FLDLN2
                        fpuPush(M_LN2);
                        fpuSetPointers(0, 0xD9ED);
                        break;
                     case 0xE:   //FLDZ
                        fpuPush(0.0);
                        fpuSetPointers(0, 0xD9EE);
                        break;
                  }
                  break;
               case 0xF0:
                  switch (lower) {
                     case 0x2:   //FPTAN
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(tanl(*fp80));
                           fpuPush(1.0L);
                        }
                        fpuSetPointers(0, 0xD9F2);
                        break;
                     case 0x5:   //FPREM1
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(remainderl(*fp80, fpuGet(0)));
                        }
                        fpuSetPointers(0, 0xD9F5);
                        break;
                     case 0x6:   //FDECSTP
                        FPU_CLEAR(FPU_C1);
                        setFpuStackTop((fpuStackTop - 1) & 7);
                        fpuSetPointers(0, 0xD9F6);
                        break;
                     case 0x7:   //FINCSTP
                        FPU_CLEAR(FPU_C1);
                        setFpuStackTop((fpuStackTop + 1) & 7);
                        fpuSetPointers(0, 0xD9F7);
                        break;
                     case 0x8:   //FPREM
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(remainderl(*fp80, fpuGet(0)));
                        }
                        fpuSetPointers(0, 0xD9F8);
                        break;
                     case 0xA:   //FSQRT
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(sqrtl(*fp80));
                        }
                        fpuSetPointers(0, 0xD9FA);
                        break;
                     case 0xB:   //FSINCOS
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(sinl(*fp80));
                           fpuPush(cosl(*fp80));
                        }
                        fpuSetPointers(0, 0xD9FB);
                        break;
                     case 0xC:   //FRNDINT
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(roundl(*fp80));
                        }
                        fpuSetPointers(0, 0xD9FC);
                        break;
                     case 0xE:   //FSIN
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(sinl(*fp80));
                        }
                        fpuSetPointers(0, 0xD9FE);
                        break;
                     case 0xF:   //FCOS
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuPush(cosl(*fp80));
                        }
                        fpuSetPointers(0, 0xD9FF);
                        break;
                  }
                  break;
            }
         }
         break;
      case 0xA: //
         if (source.type != TYPE_REG) {
            //source.addr is int*
            i32[0] = readMem(source.addr, SIZE_DWORD);
            switch (subop) {
               case 0:    //FIADD
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = i32[0] + fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 1:    //FIMUL
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = i32[0] * fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 2:    //FICOM
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  fpuCompare(fpuGet(0), *i32);
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 3:    //FICOMP
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  dbl = fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuCompare(dbl, *i32);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 4:    //FISUB
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = fpuPop() - i32[0];
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 5:    //FISUBR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = i32[0] - fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 6:    //FIDIV
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = fpuPop() / i32[0];
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
               case 7:    //FIDIVR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  *fp80 = i32[0] / fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0: //FCMOVB/FCMOVE
                  //*** need implementation
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;                  
               case 0xD0: //FCMOVBE/FCMOVU
                  //*** need implementation
                  fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  break;                  
               case 0xE0:
                  if (lower == 9) { //FUCOMPP
                     //*** need implementation
                     fpuSetPointers(source.addr, 0xDA00 | dest.modrm);
                  }
                  break;                  
            }
         }
         break;
      case 0xB: //
         if (source.type != TYPE_REG) {
            switch (subop) {
               case 0:    //FILD
                  //source.addr is int*
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(i32[0]);
                  }
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
               case 1:    //FISTTP
                  //source.addr is int*
                  *i32 = (int)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
               case 2:    //FIST
                  //source.addr is int*
                  *i32 = (int)fpuGet(0);
                  writeMem(source.addr, i32[0], SIZE_DWORD);
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
               case 3:    //FISTP
                  //source.addr is int*
                  *i32 = (int)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
               case 4:    //should not happen
                  break;
               case 5:    //FLD
                  //source.addr is long double*
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  i32[2] = readMem(source.addr + 8, SIZE_WORD);
                  fpuPush(*fp80);
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
               case 6:    //should not happen
                  break;
               case 7:    //FSTP
                  //source.addr is long double*
                  *fp80 = fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                     writeMem(source.addr + 4, i32[1], SIZE_DWORD);
                     writeMem(source.addr + 8, i32[2], SIZE_WORD);
                  }
                  fpuSetPointers(source.addr, 0xDB00 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:
                  //FCMOVNB/FCMOVNE
                  //*** need implementation
                  fpuSetPointers(0, 0xDB00 | dest.modrm);
                  break;
               case 0xD0:  //FCMOVNBE/FCMOVNU
                  //*** need implementation
                  fpuSetPointers(0, 0xDB00 | dest.modrm);
                  break;
               case 0xE0:
                  if (lower == 2) { //FNCLEX
                     fpu.status &= 0x7F00;
                  }
                  else if (lower == 3) { //FNINIT
                     fpuInit();
                  }
                  else if (lower >= 8) { //FUCOMI
                     //*** need implementation
                     fpuSetPointers(0, 0xDB00 | dest.modrm);
                  }
                  break;
               case 0xF0:  //FCOMI
                  //*** need implementation
                  fpuSetPointers(0, 0xDB00 | dest.modrm);
                  break;
            }
         }
         break;
      case 0xC: //
         if (source.type != TYPE_REG) {
            //source.addr is double*
            i32[0] = readMem(source.addr, SIZE_DWORD);
            i32[1] = readMem(source.addr + 4, SIZE_DWORD);
            switch (subop) {
               case 0:    //FADD
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = fpuPop() + *fp64;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 1:    //FMUL
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = fpuPop() * *fp64;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 2:    //FCOM
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  fpuCompare(fpuGet(0), *fp64);
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 3:    //FCOMP
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  dbl = fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuCompare(dbl, *fp64);
                  }
                  fpuSetPointers(source.addr, 0xD800 | dest.modrm);
                  break;
               case 4:    //FSUB
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = fpuPop() - *fp64;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 5:    //FSUBR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = *fp64 - fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 6:    //FDIV
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = fpuPop() / *fp64;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
               case 7:    //FDIVR
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  *fp80 = *fp64/ fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDC00 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {           //FADD  ST(i), ST(0)
                     *fp80 = *fp80 + fpuGet(0);
                  }
                  else {            //FMUL  ST(i), ST(0)
                     *fp80 = *fp80 * fpuGet(0);
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuSetPointers(0, 0xDCC0 + lower);
                  break;
               case 0xE0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower >= 8) {           //FSUB  ST(i), ST(0)
                     *fp80 = *fp80 - fpuGet(0);
                  }
                  else {                     //FSUBR  ST(i), ST(0)
                     *fp80 = fpuGet(0) - *fp80;
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuSetPointers(0, 0xDCE0 + lower);
                  break;
               case 0xF0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower >= 8) {           //FDIV  ST(i), ST(0)
                     *fp80 = *fp80 / fpuGet(0);
                  }
                  else {                     //FDIVR  ST(i), ST(0)
                     *fp80 = fpuGet(0) / *fp80;
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuSetPointers(0, 0xDCF0 + lower);
                  break;
            }
         }
         break;
      case 0xD: //
         if (source.type != TYPE_REG) {
            switch (subop) {
               case 0:    //FLD
                  //source.addr is double*
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp64);
                  }
                  fpuSetPointers(source.addr, 0xDD00 | dest.modrm);
                  break;
               case 1:    //FISTTP
                  *i64 = (unsigned long long)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                     writeMem(source.addr + 4, i32[1], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xDD00 | dest.modrm);
                  break;
               case 2:    //FST
                  //source.addr is double*
                  *fp64 = (double)fpuGet(0);
                  writeMem(source.addr, i32[0], SIZE_DWORD);
                  writeMem(source.addr + 4, i32[1], SIZE_DWORD);
                  fpuSetPointers(source.addr, 0xDD00 | dest.modrm);
                  break;
               case 3:    //FSTP
                  //source.addr is double*
                  *fp64 = (double)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                     writeMem(source.addr + 4, i32[1], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xDD00 | dest.modrm);
                  break;
               case 4:    //FRSTOR
                  fpuLoadEnv(source.addr);
                  source.addr += 28;
                  for (int m = 0; m < 8; m++) {
                     unsigned short *s = (unsigned short*)&fpu.r[m];
                     for (int n = 0; n < 5; n++) {
                        s[n] = readMem(source.addr, SIZE_WORD);
                        source.addr += 2;
                     }
                  }
                  break;
               case 5:    //should not happen
                  break;
               case 6:    //FSAVE
                  fpuStoreEnv(source.addr);
                  source.addr += 28;
                  for (int m = 0; m < 8; m++) {
                     unsigned short *s = (unsigned short*)&fpu.r[m];
                     for (int n = 0; n < 5; n++) {
                        writeMem(source.addr, s[n], SIZE_WORD);
                        source.addr += 2;
                     }
                  }
                  break;
               case 7:    //FSTSW
                  opsize = SIZE_WORD;
                  storeOperand(&source, fpu.status);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:      //FFREE
                  if (lower < 8) {
                     fpuSetTag(lower, FPU_EMPTY_TAG);
                     fpuSetPointers(0, 0xDDC0 + lower);
                  }
                  break;
               case 0xD0:      //FST
                  //*** need implementation
                  fpuSetPointers(0, 0xDD00 | dest.modrm);
                  break;
               case 0xE0:      //FUCOM
                  //*** need implementation
                  fpuSetPointers(0, 0xDE00 | dest.modrm);
                  break;
               case 0xF0:
                  //should not happen
                  break;
            }
         }
         break;
      case 0xE: //
         if (source.type != TYPE_REG) {
            //source.addr is short*
            i32[0] = readMem(source.addr, SIZE_WORD);
            switch (subop) {
               case 0:    //FIADD
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = *i16 + fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 1:    //FIMUL
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = *i16 * fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 2:    //FICOM
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  fpuCompare(fpuGet(0), *i16);
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 3:    //FICOMP
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  dbl = fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuCompare(dbl, *i16);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 4:    //FISUB
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = fpuPop() - *i16;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 5:    //FISUBR
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = *i16 - fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 6:    //FIDIV
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = fpuPop() / *i16;
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
               case 7:    //FIDIVR
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  *fp80 = *i16 / fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     fpuPush(*fp80);
                  }
                  fpuSetPointers(source.addr, 0xDE00 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xC0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower < 8) {          //FADDP  ST(i), ST(0)
                     *fp80 = *fp80 + fpuGet(0);
                  }
                  else {          //FMULP  ST(i), ST(0)
                     *fp80 = *fp80 * fpuGet(0);
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuPop();
                  fpuSetPointers(0, 0xDEC0 + lower);
                  break;
               case 0xD0:
                  //there should be no other cases here
                  if (lower == 9) {   //FCOMPP
                     dbl = fpuPop();
                     if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                        *fp80 = fpuPop();
                        if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                           fpuCompare(dbl, *fp80);
                        }
                     }
                     fpuSetPointers(0, 0xDED9);
                  }
                  break;
               case 0xE0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower >= 8) {          //FSUBP  ST(i), ST(0)
                     *fp80 = *fp80 - fpuGet(0);
                  }
                  else {               //FSUBRP  ST(i), ST(0)
                     *fp80 = fpuGet(0) - *fp80;
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuPop();
                  fpuSetPointers(0, 0xDEE0 + lower);
                  break;
               case 0xF0:
                  *fp80 = fpuGet(lower & 7);
                  if (lower >= 8) {          //FDIVP  ST(i), ST(0)
                     *fp80 = *fp80 / fpuGet(0);
                  }
                  else {                  //FDIVRP  ST(i), ST(0)
                     *fp80 = fpuGet(0) / *fp80;
                  }
                  fpuSet(lower & 7, *fp80);
                  fpuPop();
                  fpuSetPointers(0, 0xDEF0 + lower);
                  break;
            }
         }
         break;
      case 0xF: //
         if (source.type != TYPE_REG) {
            switch (subop) {
               case 0:    //FILD
                  //source.addr is short*
                  i32[0] = readMem(source.addr, SIZE_WORD);
                  fpuPush(*i16);
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
               case 1:    //FISTTP
                  //source.addr is short*
                  *i16 = (short)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_WORD);
                  }
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
               case 2:    //FIST
                  //source.addr is short*
                  *i16 = (short)fpuGet(0);
                  writeMem(source.addr, i32[0], SIZE_WORD);
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
               case 3:    //FISTP
                  //source.addr is short*
                  *i16 = (short)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_WORD);
                  }
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
               case 4:    //FBLD
                  //source.addr is packed bcd* (10 bytes)
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  i32[2] = readMem(source.addr + 8, SIZE_WORD);
                  break;
               case 5:    //FILD
                  //source.addr is unsigned long long*
                  i32[0] = readMem(source.addr, SIZE_DWORD);
                  i32[1] = readMem(source.addr + 4, SIZE_DWORD);
                  fpuPush(*fp80);
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
               case 6:    //FBSTP
                  //source.addr is packed bcd* (10 bytes)
                  //*** need implementation
                  fpuSetPointers(0, 0xDF00 | dest.modrm);
                  break;
               case 7:    //FISTP
                  //source.addr is unsigned long long*
                  *i64 = (unsigned long long)fpuPop();
                  if (FPU_MASK_GET(FPU_INVALID) || !FPU_GET(FPU_STACKFAULT)) {
                     writeMem(source.addr, i32[0], SIZE_DWORD);
                     writeMem(source.addr + 4, i32[1], SIZE_DWORD);
                  }
                  fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  break;
            }
         }
         else {  //modrm >= 0xC0
            int upper = dest.modrm & 0xF0;
            int lower = dest.modrm & 0x0F;
            switch (upper) {
               case 0xE0:        //FSTSW AX
                  if (dest.modrm == 0xE0) {
                     eax = (eax & 0xFFFF0000) | fpu.status;
                  }
                  else if (lower >= 8) { //FUCOMIP
                     //*** need implementation
                     fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  }
                  break;
               case 0xF0: //FCOMIP
                  if (lower < 8) {
                     //*** need implementation
                     fpuSetPointers(source.addr, 0xDF00 | dest.modrm);
                  }
                  break;
            }
         }
         break;
   }
   return 1;
}

//handle instructions that begin w/ 0xEn
int doFourteen() {
   unsigned char op = opcode & 0x0F;
   unsigned int disp;
   unsigned int cond;
   if (op < 4) {
      disp = fetch(SIZE_BYTE);
      if (op < 3) { //LOOPNE/LOOPNZ, LOOPE/LOOPZ, LOOP
         cond = op == 2 ? 1 : op == 0 ? xNZ : xZ;
         dest.addr = ECX;
         dest.type = TYPE_REG;
         storeOperand(&dest, getOperand(&dest) - 1);
         if (getOperand(&dest) && cond) {
            cpu.eip += sebd(disp);
         }
      }
      else {  //JCXZ
         if ((ecx & SIZE_MASKS[opsize]) == 0) {
            cpu.eip += sebd(disp);
         }
      }
   }
   switch (op) {
      case 4:  //IN
         fetchu(SIZE_BYTE);  //port number
         break;
      case 5:  //IN
         fetchu(SIZE_BYTE);  //port number
         break;
      case 6:  //OUT
         fetchu(SIZE_BYTE);  //port number
         break;
      case 7: //OUT
         fetchu(SIZE_BYTE);  //port number
         break;
      case 8: //CALL
         disp = fetch(opsize);
         if (opsize == SIZE_WORD) disp = sewd(disp);
         doCall(cpu.eip + disp);
         break;
      case 9: //JMP
         disp = fetch(opsize);
         if (opsize == SIZE_WORD) disp = sewd(disp);
         cpu.eip += disp;
         break;
      case 0xA: //JMP
         break;
      case 0xB: //JMP
         disp = sebd(fetch(SIZE_BYTE));
         cpu.eip += disp;
         break;
      case 0xC: //IN
         break;
      case 0xD: //IN
         break;
      case 0xE: //OUT
         break;
      case 0xF: //OUT
         break;
   }
   return 1;
}

//handle instructions that begin w/ 0xFn
int doFifteen() {
   unsigned char op = opcode & 0x0F;
   unsigned long long temp, divisor;
   if ((op & 7) > 5) { //subgroup
      unsigned char subop;
      fetchOperands(&source, &dest);
      subop = source.addr;
      if (op < 8) { //Unary group 3
         if (op == 6) opsize = SIZE_BYTE;
         switch (subop) {
            case 0: //TEST
               AND(getOperand(&dest), fetch(opsize));
               break;
            case 2: //NOT
               storeOperand(&dest, ~getOperand(&dest));
               break;
            case 3: //NEG
               temp = getOperand(&dest);
               storeOperand(&dest, sub(0, (unsigned int)temp));
               if (temp) SET(xCF);
               else CLEAR(xCF);
               break;
            case 4: case 5: //MUL: IMUL: (CF/OF incorrect for IMUL
               source.addr = dest.addr;
               source.type = dest.type;
               temp = getOperand(&source);
               dest.addr = EAX;            //change dest to EAX
               dest.type = TYPE_REG;
               temp *= getOperand(&dest); //multiply by EAX
               if (opsize == SIZE_BYTE) {
                  opsize = SIZE_WORD;
                  storeOperand(&dest, (unsigned int)temp);
                  temp >>= 8;
               }
               else {
                  storeOperand(&dest, (unsigned int)temp);
                  dest.addr = EDX;
                  temp >>= opsize == SIZE_WORD ? 16 : 32;
                  storeOperand(&dest, (unsigned int)temp);
               }
               if (temp) SET(xCF | xOF);
               else CLEAR(xCF | xOF);
               break;
            case 6: case 7: //DIV: IDIV: (does this work for IDIV?)
               source.addr = dest.addr;
               source.type = dest.type;
               if (opsize == SIZE_BYTE) temp = eax & 0xFFFF;
               else if (opsize == SIZE_WORD) {
                  temp = ((edx & 0xFFFF) << 16) | (eax & 0xFFFF);
               }
               else {
                  temp = edx;
                  temp <<= 32;
                  temp |= eax;
               }
               divisor = getOperand(&source);
               if (divisor == 0) {
                  initiateInterrupt(0, cpu.initial_eip);
               }
               else {
                  dest.addr = EAX;
                  dest.type = TYPE_REG;
                  storeOperand(&dest, (unsigned int) (temp / divisor));
                  dest.addr = EDX;
                  storeOperand(&dest, (unsigned int) (temp % divisor));
               }
               break;
         }
      }
      else { //group4/5
         unsigned int result;
         if (op == 0xE) opsize = SIZE_BYTE; //should only be a group 4
         if (subop < 2) { //INC/DEC
            if (subop == 0) result = inc(getOperand(&dest));
            else result = dec(getOperand(&dest));
            storeOperand(&dest, result);
         }
         else {
            switch (subop) {
               case 2: //CALLN
                  doCall(getOperand(&dest));
                  break;
               case 3: //CALLF
                  break;
               case 4: { //JMPN
                     unsigned int addr = getOperand(&dest);
                     if (!checkJumpFunction(addr)) {
                        cpu.eip = addr;
                     }
                     break;
                  }
               case 5: //JMPF
                  break;
               case 6: //PUSH
                  push(getOperand(&dest), opsize);
                  break;
            }
         }
      }
   }
   else {
      switch (op) {
         case 0:
            prefix |= PREFIX_LOCK;
            return 0;
         case 1: //0xF1 icebp
            msg("ICEBP at 0x%x\n", cpu.eip);
            initiateInterrupt(1, cpu.initial_eip);
            break;
         case 2:
            prefix |= PREFIX_REPNE;
            return 0;
         case 3:
            prefix |= PREFIX_REP;
            return 0;
         case 4:  //HLT
            break;
         case 5:  //CMC
            cpu.eflags ^= xCF;
            break;
         case 8: //CLC
            CLEAR(xCF);
            break;
         case 9: //STC
            SET(xCF);
            break;
         case 0xA: //CLI
            CLEAR(xIF);
            break;
         case 0xB: //STI
            SET(xIF);
            break;
         case 0xC: //CLD
            CLEAR(xDF);
            break;
         case 0xD: //STD
            SET(xDF);
            break;
      }
   }
   return 1;
}

int doSet(unsigned char cc) {
   int set = 0;
   fetchOperands(&source, &dest);
   opsize = SIZE_BYTE;
   switch (cc) {
      case 0: //SO
         set = xO;
         break;
      case 1: //SNO
         set = xNO;
         break;
      case 2: //B/NAE/C
         set = xB;
         break;
      case 3: //NB/AE/NC
         set = xNB;
         break;
      case 4:  //E/Z
         set = xZ;
         break;
      case 5:  //NE/NZ
         set = xNZ;
         break;
      case 6:  //BE/NA
         set = xBE;
         break;
      case 7:  //NBE/A
         set = xA;
         break;
      case 8: //S
         set = xS;
         break;
      case 9: //NS
         set = xNS;
         break;
      case 0xA: //P/PE
         set = xP;
         break;
      case 0xB: //NP/PO
         set = xNP;
         break;
      case 0xC: //L/NGE
         set = xL;
         break;
      case 0xD: //NL/GE
         set = xGE;
         break;
      case 0xE: //LE/NG
         set = xLE;
         break;
      case 0xF: //NLE/G
         set = xG;
         break;
   }
   storeOperand(&dest, set ? 1 : 0);
   return 1;
}

unsigned int doBitReset(unsigned int val, int mask) {
   return val &= ~mask;
}

unsigned int doBitSet(unsigned int val, int mask) {
   return val |= mask;
}

unsigned int doBitComplement(unsigned int val, int mask) {
   return val ^= mask;
}

unsigned int doBitTest(unsigned int val, int /*mask*/) {
   return val;
}

void doBitOp(unsigned int (*bitop)(unsigned int, int)) {
   unsigned int result;
   int bitpos;
//   msg("fetching bitop operands, eip = %x\n", cpu.eip);
   fetchOperands(&source, &dest);
//   msg("fetched bitop operands, eip now = %x\n", cpu.eip);
   bitpos = getOperand(&source);
   if (dest.type == TYPE_REG) {
      bitpos &= (opsize == SIZE_DWORD) ? ~32 : ~16;
   }
   else {  //TYPE_MEM
      dest.addr += bitpos >> 3;
      opsize = SIZE_BYTE;
      bitpos &= ~8;
   }
   result = getOperand(&dest);
   bitpos = 1 << bitpos;
   if (result & bitpos) SET(xCF);
   else CLEAR(xCF);
   storeOperand(&dest, (*bitop)(result, bitpos));
//   msg("bitop complete\n");
}

void doBitOpGrp8() {
   unsigned int result;
   int bitpos;
   fetchOperands(&source, &dest);
   bitpos = fetchu(SIZE_BYTE) & ~32;
   if (dest.type == TYPE_REG) {
      if (opsize == SIZE_WORD) bitpos &= ~16;
   }
   else {  //TYPE_MEM
      dest.addr += bitpos >> 3;
      opsize = SIZE_BYTE;
      bitpos &= ~8;
   }
   result = getOperand(&dest);
   bitpos = 1 << bitpos;
   if (result & bitpos) SET(xCF);
   else CLEAR(xCF);
   switch (source.addr) {
   case 4:
      break;
   case 5:
      result = doBitSet(result, bitpos);
      break;
   case 6:
      result = doBitReset(result, bitpos);
      break;
   case 7:
      result = doBitComplement(result, bitpos);
      break;
   }
   storeOperand(&dest, result);
}

struct cpuids {
   uint32_t _eax;
   uint32_t _ebx;
   uint32_t _ecx;
   uint32_t _edx;
};

static struct cpuids cpuid_basic[] = {
   { 0x00000005, 0x756e6547, 0x6c65746e, 0x49656e69 },
   { 0x00040651, 0x00000800, 0x00000209, 0x078bfbff },
   { 0x76036301, 0x00f0b5ff, 0x00000000, 0x00c10000 },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000 }, /* special */
   { 0x00000040, 0x00000040, 0x00000000, 0x00000000 }
};

static struct cpuids cpuid_ext[] = {
   { 0x80000008, 0x00000000, 0x00000000, 0x00000000 },
   { 0x00000000, 0x00000000, 0x00000001, 0x28100800 },
   { 0x65746e49, 0x2952286c, 0x726f4320, 0x4d542865 },
   { 0x35692029, 0x3532342d, 0x43205538, 0x40205550 },
   { 0x342e3220, 0x7a484730, 0x00000000, 0x00000000 },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
   { 0x00000000, 0x00000000, 0x01006040, 0x00000000 },
   { 0x00000000, 0x00000000, 0x00000000, 0x00000000 },
   { 0x00003027, 0x00000000, 0x00000000, 0x00000000 }
};

static struct cpuids cpuid_dfl = {
   0x00000007, 0x00000340, 0x00000340, 0x00000000
};

struct cpuids cpuid_leaf4[] = {
   { 0x00000021, 0x01c0003f, 0x0000003f, 0x00000000 },
   { 0x00000021, 0x01c0003f, 0x0000003f, 0x00000000 },
   { 0x00000041, 0x05c0003f, 0x00000fff, 0x00000000 }
};

#define N(t) (sizeof(t) / sizeof(t[0]))

void do_cpuid() {
   // vmx has the entry registers, regs has the exit registers
   struct cpuids *leaf;

   if (eax == 4 && ecx < N(cpuid_leaf4)) {
      leaf = &cpuid_leaf4[ecx];
   }
   else if (eax < N(cpuid_basic)) {
      leaf = &cpuid_basic[eax];
   }
   else if (eax - 0x80000000 < N(cpuid_ext)) {
      leaf = &cpuid_ext[eax - 0x80000000];
   }
   else {
      leaf = &cpuid_dfl;
   }
   eax = leaf->_eax;
   ebx = leaf->_ebx;
   ecx = leaf->_ecx;
   edx = leaf->_edx;
}

int doEscape() {
   unsigned int result, regs, upper, lower;
   int op1, op2, n;
   opcode = fetchu(SIZE_BYTE);
   upper = opcode >> 4;
   lower = opcode & 0xF;
   switch (upper) {
      case 0: //LGDT, LIDT, SGDT, SIDT among others
         switch (lower) {
            case 0: case 1: { //SGDT / SIDT
               DescriptorTableReg *dtr = opcode ? &cpu.idtr : &cpu.gdtr;
               decodeAddressingModes();
               opsize = SIZE_WORD;
               storeOperand(&dest, dtr->limit);
               opsize = SIZE_DWORD;
               dest.addr += 2;
               storeOperand(&dest, dtr->base);
               break;
            }
            case 9:   //UD2
               initiateInterrupt(6, cpu.initial_eip);
               break;
         }
         break;
      case 1:
         switch (lower) {
            case 0: {        
               fetchOperands(&dest, &source);
               if (prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {   //MOVSS
                     sse2.xmm.i[dest.addr][0] = sse2.xmm.i[source.addr][0];
                  }
                  else {
                     sse2.xmm.i[dest.addr][0] = readMem(source.addr, SIZE_DWORD);
                     sse2.xmm.i[dest.addr][1] = 0;
                     sse2.xmm.ll[dest.addr][1] = 0;
                  }
               }
               else if (prefix & PREFIX_REPNE) {   //MOVSD
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][0], 8);
                     sse2.xmm.ll[dest.addr][1] = 0;
                  }
               }
//               else if (prefix & PREFIX_SIZE) {   //MOVUPD
               else {   //MOVUPD, MOVUPS
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][0], 16);
                  }
               }
               break;
            }
            case 1: {
               fetchOperands(&source, &dest);
               if (prefix & PREFIX_REP) {
                  if (dest.type == TYPE_REG) {     //MOVSS
                     sse2.xmm.i[dest.addr][0] = sse2.xmm.i[source.addr][0];
                  }
                  else {
                     writeMem(dest.addr, sse2.xmm.i[source.addr][0], SIZE_DWORD);
                  }
               }
               else if (prefix & PREFIX_REPNE) {    //MOVSD
                  if (dest.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                  }
                  else {
                     writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 8);
                  }
               }
//               else if (prefix & PREFIX_SIZE) {    //MOVUPD
               else {    //MOVUPD, MOVUPS
                  if (dest.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 16);
                  }
               }
               break;
            }
            case 2: {
               fetchOperands(&dest, &source);
               if (source.type == TYPE_REG) {    //MOVHLPS
                  sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][1];
               }
//               else if (prefix & PREFIX_SIZE) {
               else {     //MOVLPS, MOVLPD
                  readBuffer(source.addr, &sse2.xmm.i[dest.addr][0], 8);
               }
               break;
            }
            case 3: {    //MOVLPD, MOVLPS
               fetchOperands(&source, &dest);
//               if (prefix & PREFIX_SIZE) {
               writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 8);
//               }
               break;
            }
            case 6: {    // MOVHPD, MOVHPS
               fetchOperands(&dest, &source);
               if (prefix & PREFIX_SIZE) {
                  readBuffer(source.addr, &sse2.xmm.i[dest.addr][2], 8);
               }
               else {
                  if (source.type == TYPE_REG) {  //MOVLHPS
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][0];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][2], 8);
                  }
               }
               break;
            }
            case 7: {    // MOVHPD, MOVHPS
               fetchOperands(&source, &dest);
               if (prefix & PREFIX_SIZE) {
                  writeBuffer(dest.addr, &sse2.xmm.i[source.addr][2], 8);
               }
               else {
                  writeBuffer(dest.addr, &sse2.xmm.i[source.addr][2], 8);
               }
               break;
            }
            //0x19-0x1f are NOPs
            case 0xf: {
               fetchOperands(&source, &dest);
               break;
            }
         }
         break;
      case 2: //MOV to/from control/debug registers
         switch (lower) {
            case 0: //mov from control registers
               regs = fetchu(SIZE_BYTE);
               cpu.general[regs & 7] = cpu.control[(regs >> 3) & 7];
               break;
            case 1: //mov from debug registers
               regs = fetchu(SIZE_BYTE);
               cpu.general[regs & 7] = cpu.debug_regs[(regs >> 3) & 7];
               break;
            case 2:  //mov to control registers
               regs = fetchu(SIZE_BYTE);
               cpu.control[(regs >> 3) & 7] = cpu.general[regs & 7];
               break;
            case 3:  //mov to debug registers
               regs = fetchu(SIZE_BYTE);
               cpu.debug_regs[(regs >> 3) & 7] = cpu.general[regs & 7];
               break;
            case 0x8:  //MOVAPD, MOVAPS
               fetchOperands(&dest, &source);
//               if (prefix & PREFIX_SIZE) {
               if (dest.type == TYPE_REG) {
                  sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                  sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
               }
               else {
                  readBuffer(source.addr, &sse2.xmm.i[dest.addr][0], 16);
               }
//               }
               break;
            case 0x9:  //MOVAPD, MOVAPS
               fetchOperands(&source, &source);
//               if (prefix & PREFIX_SIZE) {
               if (dest.type == TYPE_REG) {
                  sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                  sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
               }
               else {
                  writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 16);
               }
//               }
               break;
            case 0xB:  //MOVNTPD, MOVNTPS
               fetchOperands(&source, &dest);
//               if (prefix & PREFIX_SIZE) {
                  writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 16);
//               }
               break;
         }
         break;
      case 3: { //
         switch (lower) {
            case 1: //RDTSC
               edx = (unsigned int) tsc.high;
               eax = (unsigned int) tsc.low;
               break;
            case 4: //SYSENTER
               doSysenter();
               break;
            case 5: //SYSEXIT
               break;
         }
         break;
      }
      case 4: { //CMOVcc
         int doMove = 0;
         switch (lower) {
            case 0:      //CMOVO
               doMove = xO;
               break;
            case 1:      //CMOVNO
               doMove = xNO;
               break;
            case 2:      //CMOVB, CMOVC, CMOVNAE
               doMove = xB;
               break;
            case 3:      //CMOVAE, CMOVNB, CMOVNC
               doMove = xNB;
               break;
            case 4:      //CMOVE, CMOVZ
               doMove = xZ;
               break;
            case 5:      //CMOVNE, CMOVNZ
               doMove = xNZ;
               break;
            case 6:      //CMOVBE, CMOVNA
               doMove = xBE;
               break;
            case 7:      //CMOVA, CMOVNBE
               doMove = xA;
               break;
            case 8:      //CMOVS
               doMove = xS;
               break;
            case 9:      //CMOVNS
               doMove = xNS;
               break;
            case 0xA:      //CMOVP, CMOVPE
               doMove = xP;
               break;
            case 0xB:      //CMOVNP, CMOVPO
               doMove = xNP;
               break;
            case 0xC:      //CMOVL, CMOVNGE
               doMove = xL;
               break;
            case 0xD:      //CMOVGE, CMOVNL
               doMove = xGE;
               break;
            case 0xE:      //CMOVLE, CMOVNG
               doMove = xLE;
               break;
            case 0xF:      //CMOVG, CMOVNLE
               doMove = xG;
               break;
         }
         fetchOperands(&dest, &source);
         if (doMove) {
            storeOperand(&dest, getOperand(&source));
         }
         break;
      }
      case 5: {
         switch (lower) {
            case 0:
               fetchOperands(&dest, &source);
               opsize = SIZE_DWORD;
               op1 = 0;
               if (prefix & PREFIX_SIZE) {  //MOVMSKPS
                  if (sse2.xmm.b[source.addr][8] & 0x80) {
                     op1 |= 1;
                  }
                  if (sse2.xmm.b[source.addr][15] & 0x80) {
                     op1 |= 2;
                  }
               }
               else {      //MOVMSKPD
                  for (int i = 0; i < 4; i++) {
                     if (sse2.xmm.b[source.addr][i * 4 + 3] & 0x80) {
                        op1 |= (1 << i);
                     }
                  }
               }
               storeOperand(&dest, op1);
               break;
            case 1:      //SQRTPS, SQRTSS, SQRTPD, SQRTSD
               break;
            case 2:      //RSQRTPS, RSQRTSS
               break;
            case 3:      //RCPPS, RCPSS
               break;
            case 4:      //ANDPS, ANDPD
               fetchOperands(&dest, &source);
//               if (prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] &= sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] &= sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     for (int i = 0; i < 4; i++) {
                        sse2.xmm.i[dest.addr][i] &= readMem(source.addr + i * 4, SIZE_DWORD);
                     }
                  }
//               }
               break;
            case 5:      //ANDNPS, ANDNPD
               fetchOperands(&dest, &source);
//               if (prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = ~sse2.xmm.ll[dest.addr][0] & sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] = ~sse2.xmm.ll[dest.addr][0] & sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     for (int i = 0; i < 4; i++) {
                        sse2.xmm.i[dest.addr][i] = ~sse2.xmm.i[dest.addr][i] & readMem(source.addr + i * 4, SIZE_DWORD);
                     }
                  }
//               }
               break;
            case 6:      //ORPS, ORPD
               fetchOperands(&dest, &source);
//               if (prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] |= sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] |= sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     for (int i = 0; i < 4; i++) {
                        sse2.xmm.i[dest.addr][i] |= readMem(source.addr + i * 4, SIZE_DWORD);
                     }
                  }
//               }
               break;
            case 7:      //XORPS, XORPD
               fetchOperands(&dest, &source);
//               if (prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] ^= sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] ^= sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     for (int i = 0; i < 4; i++) {
                        sse2.xmm.i[dest.addr][i] ^= readMem(source.addr + i * 4, SIZE_DWORD);
                     }
                  }
//               }
               break;
            case 8:      //ADDPS, ADDSS, ADDPD, ADDSD
               break;
            case 9:      //MULPS, MULSS, MULPD, MULSD
               break;
            case 0xA:      //CVTPS2PD, CVTSS2SD, CVTPD2PS, CVTSD2SS
               break;
            case 0xB:      //CVTDQ2PS, CVTPS2DQ, CVTTPS2DQ
               break;
            case 0xC:      //SUBPS, SUBSS, SUBPD, SUBSD
               break;
            case 0xD: {
               fetchOperands(&dest, &source);
               double dbl[2], *d;
               float flt[4], *f;
               if (prefix & PREFIX_SIZE) {    //MINPD
                  if (source.type == TYPE_REG) {
                     d = &sse2.xmm.d[source.addr][0];
                  }
                  else {
                     d = dbl;
                     readBuffer(source.addr, dbl, 16);
                  }
                  if (d[0] < sse2.xmm.d[dest.addr][0]) sse2.xmm.d[dest.addr][0] = d[0];
                  if (d[1] < sse2.xmm.d[dest.addr][1]) sse2.xmm.d[dest.addr][1] = d[1];
               }
               else if (prefix & PREFIX_REP) {    //MINSS
                  if (source.type == TYPE_REG) {
                     f = &sse2.xmm.f[source.addr][0];
                  }
                  else {
                     f = flt;
                     readBuffer(source.addr, flt, 4);
                  }
                  if (f[0] < sse2.xmm.f[dest.addr][0]) {
                     sse2.xmm.f[dest.addr][0] = f[0];
                  }
               }
               else if (prefix & PREFIX_REPNE) {   //MINSD
                  if (source.type == TYPE_REG) {
                     d = &sse2.xmm.d[source.addr][0];
                  }
                  else {
                     d = dbl;
                     readBuffer(source.addr, dbl, 8);
                  }
                  if (d[0] < sse2.xmm.d[dest.addr][0]) {
                     sse2.xmm.d[dest.addr][0] = d[0];
                  }
               }
               else {   //MINPS
                  if (source.type == TYPE_REG) {
                     f = &sse2.xmm.f[source.addr][0];
                  }
                  else {
                     f = flt;
                     readBuffer(source.addr, flt, 16);
                  }
                  for (int i = 0; i < 4; i++) {
                     if (f[i] < sse2.xmm.f[dest.addr][i]) {
                        sse2.xmm.f[dest.addr][i] = f[i];
                     }
                  }
               }
               break;
            }
            case 0xE: {     //DIVPS, DIVSS, DIVPD, DIVSD
               break;
            }
            case 0xF: {
               fetchOperands(&dest, &source);
               double dbl[2], *d;
               float flt[4], *f;
               if (prefix & PREFIX_SIZE) {    //MAXPD
                  if (source.type == TYPE_REG) {
                     d = &sse2.xmm.d[source.addr][0];
                  }
                  else {
                     d = dbl;
                     readBuffer(source.addr, dbl, 16);
                  }
                  if (d[0] > sse2.xmm.d[dest.addr][0]) sse2.xmm.d[dest.addr][0] = d[0];
                  if (d[1] > sse2.xmm.d[dest.addr][1]) sse2.xmm.d[dest.addr][1] = d[1];
               }
               else if (prefix & PREFIX_REP) {    //MAXSS
                  if (source.type == TYPE_REG) {
                     f = &sse2.xmm.f[source.addr][0];
                  }
                  else {
                     f = flt;
                     readBuffer(source.addr, flt, 4);
                  }
                  if (f[0] > sse2.xmm.f[dest.addr][0]) {
                     sse2.xmm.f[dest.addr][0] = f[0];
                  }
               }
               else if (prefix & PREFIX_REPNE) {   //MAXSD
                  if (source.type == TYPE_REG) {
                     d = &sse2.xmm.d[source.addr][0];
                  }
                  else {
                     d = dbl;
                     readBuffer(source.addr, dbl, 8);
                  }
                  if (d[0] > sse2.xmm.d[dest.addr][0]) {
                     sse2.xmm.d[dest.addr][0] = d[0];
                  }
               }
               else {   //MAXPS
                  if (source.type == TYPE_REG) {
                     f = &sse2.xmm.f[source.addr][0];
                  }
                  else {
                     f = flt;
                     readBuffer(source.addr, flt, 16);
                  }
                  for (int i = 0; i < 4; i++) {
                     if (f[i] > sse2.xmm.f[dest.addr][i]) {
                        sse2.xmm.f[dest.addr][i] = f[i];
                     }
                  }
               }
               break;
            }
         }
         break;
      }
      case 6:
         switch (lower) {
            case 0: {    //PUNPCKLBW
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 7;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 3;
               }
               for (int i = n; i >= 0; i--) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i, SIZE_BYTE);
                  }
                  d[i * 2] = d[i];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 1: {    //PUNPCKLWD
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 3;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 1;
               }
               for (int i = n; i >= 0; i--) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  d[i * 2] = d[i];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 2: {   //PUNPCKLDQ
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 1;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 0;
               }
               for (int i = n; i >= 0; i--) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i * 2] = d[i];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 3: {   //PACKSSWB
               fetchOperands(&dest, &source);
               short *d = (short*)fpu.r[dest.addr].s;
               char *o = (char*)fpu.r[dest.addr].b;
               short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = (short*)fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 7;
                  d = (short*)&sse2.xmm.w[dest.addr][0];
                  o = (char*)&sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = (short*)&sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 3;
               }
               for (int i = n; i >= 0; i--) {
                  short v = d[i];
                  if (v > 127) v = 127;
                  else if (v < -128) v = -128;
                  o[i + n + 1] = (unsigned char)v;
               }
               for (int i = n; i >= 0; i--) {
                  short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  if (v > 127) v = 127;
                  else if (v < -128) v = -128;
                  o[i] = (unsigned char)v;
               }
               break;
            }
            case 4:    //PCMPGTB
               break;
            case 5:    //PCMPGTW
               break;
            case 6:    //PCMPGTD
               break;
            case 7: {   //PACKUSWB
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned char *o = fpu.r[dest.addr].b;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 7;
                  d = &sse2.xmm.w[dest.addr][0];
                  o = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 3;
               }
               for (int i = n; i >= 0; i--) {
                  unsigned short v = d[i];
                  if (v > 255) v = 255;
                  o[i + n + 1] = (unsigned char)v;
               }
               for (int i = n; i >= 0; i--) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  if (v > 255) v = 255;
                  o[i] = (unsigned char)v;
               }
               break;
            }
            case 8: {   //PUNPCKHBW
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i + n];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i + n, SIZE_BYTE);
                  }
                  d[i * 2] = d[i + n];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 9: {    //PUNPCKHWD
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i + n];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + (i + n) * 2, SIZE_WORD);
                  }
                  d[i * 2] = d[i + n];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 0xA: {   //PUNPCKHDQ
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 2;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 1;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i + n];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + (i + n) * 4, SIZE_DWORD);
                  }
                  d[i * 2] = d[i + n];
                  d[i * 2 + 1] = v;
               }
               break;
            }
            case 0xB: {   //PACKSSDW
               fetchOperands(&dest, &source);
               int *d = (int*)fpu.r[dest.addr].i;
               short *o = (short*)fpu.r[dest.addr].s;
               int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = (int*)fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 3;
                  d = (int*)&sse2.xmm.i[dest.addr][0];
                  o = (short*)&sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = (int*)&sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 1;
               }
               for (int i = n; i >= 0; i--) {
                  int v = d[i];
                  if (v > 0x7FFF) v = 0x7FFF;
                  else if (v < -32768) v = -32768;
                  o[i + n + 1] = (unsigned short)v;
               }
               for (int i = n; i >= 0; i--) {
                  int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  if (v > 0x7FFF) v = 0x7FFF;
                  else if (v < -32768) v = -32768;
                  o[i] = (unsigned short)v;
               }
               break;
            }
            case 0xC: {   //PUNPCKLQDQ
               if (prefix & PREFIX_SIZE) {
                  fetchOperands(&dest, &source);
//                  unsigned long long *d = &sse2.xmm.ll[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][0];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][2], 8);
                  }
               }
               else {
                  //bad instruction?
               }
               break;
            }
            case 0xD: {   //PUNPCKHQDQ
               if (prefix & PREFIX_SIZE) {
                  fetchOperands(&dest, &source);
                  unsigned long long *d = &sse2.xmm.ll[dest.addr][0];
                  d[0] = d[1];
                  if (source.type == TYPE_REG) {
                     d[1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][2], 8);
                  }
               }
               else {
                  //bad instruction?
               }
               break;
            }
            case 0xE: {   //MOVD
               fetchOperands(&dest, &source);
               opsize = SIZE_DWORD;
               op1 = getOperand(&source);
               if (prefix & PREFIX_SIZE) {
                  sse2.xmm.i[dest.addr][0] = op1;
                  sse2.xmm.i[dest.addr][1] = 0;
                  sse2.xmm.ll[dest.addr][1] = 0;
               }
               else {
                  fpu.r[dest.addr].i[0] = op1;
                  fpu.r[dest.addr].i[1] = 0;
               }
               break;
            }
            case 0xF: {   //MOVDQA, MOVQ, MOVDQU
               fetchOperands(&dest, &source);
               if (prefix & PREFIX_SIZE || prefix & PREFIX_REP) {
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     for (int i = 0; i < 4; i++) {
                        sse2.xmm.i[dest.addr][i] = readMem(source.addr + i * 4, SIZE_DWORD);
                     }
                  }
               }
               else {
                  if (source.type == TYPE_REG) {
                     fpu.r[dest.addr].ll = fpu.r[source.addr].ll;
                  }
                  else {
                     readBuffer(source.addr, &fpu.r[dest.addr].i[0], 8);
                  }
               }
               break;
            }
         }
         break;
      case 7:
         switch (lower) {
            case 0: {
               fetchOperands(&dest, &source);
               unsigned char order = fetchu(SIZE_BYTE);
               if (prefix & PREFIX_REP) {   //PSHUFHW
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][0], 8);
                  }
                  for (int i = 0; i < 4; i++) {
                     unsigned int src = order & 3;
                     order >>= 2;
                     if (source.type == TYPE_REG) {
                        sse2.xmm.w[dest.addr][i + 4] = sse2.xmm.w[source.addr][src + 4];
                     }
                     else {
                        sse2.xmm.w[dest.addr][i + 4] = readMem(source.addr + 8 + src * 2, SIZE_WORD);
                     }
                  }
               }
               else if (prefix & PREFIX_REPNE) { //PSHUFLW
                  if (source.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     readBuffer(source.addr, &sse2.xmm.i[dest.addr][2], 8);
                  }
                  for (int i = 0; i < 4; i++) {
                     unsigned int src = order & 3;
                     order >>= 2;
                     if (source.type == TYPE_REG) {
                        sse2.xmm.w[dest.addr][i] = sse2.xmm.w[source.addr][src];
                     }
                     else {
                        sse2.xmm.w[dest.addr][i] = readMem(source.addr + src * 2, SIZE_WORD);
                     }
                  }
               }
               else {      //PSHUFD, //PSHUFW
                  for (int i = 0; i < 4; i++) {
                     unsigned int src = order & 3;
                     order >>= 2;
                     if (source.type == TYPE_REG) {
                        if (prefix & PREFIX_SIZE) {
                           sse2.xmm.i[dest.addr][i] = sse2.xmm.i[source.addr][src];
                        }
                        else {
                           fpu.r[dest.addr].s[i] = fpu.r[source.addr].s[src];
                        }
                     }
                     else {
                        if (prefix & PREFIX_SIZE) {
                           sse2.xmm.i[dest.addr][i] = readMem(source.addr + src * 4, SIZE_DWORD);
                        }
                        else {
                           fpu.r[dest.addr].s[i] = readMem(source.addr + src * 2, SIZE_WORD);
                        }
                     }
                  }
               }
               break;
            }
            case 1: {
               fetchOperands(&dest, &source);
               switch (dest.addr) {
                  case 2: {    //PSRLW mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned short *d = fpu.r[dest.addr].s;
                     if (prefix & PREFIX_SIZE) {
                        n = 8;
                        d = &sse2.xmm.w[dest.addr][0];
                     }
                     else {
                        n = 4;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 15) {
                           d[i] = 0;
                        }
                        else {
                           d[i] >>= shift;
                        }
                     }
                     break;
                  }
                  case 4: {    //PSRAW mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     if (shift > 15) shift = 15;
                     short *d = (short*)fpu.r[dest.addr].s;
                     if (prefix & PREFIX_SIZE) {
                        n = 8;
                        d = (short*)&sse2.xmm.w[dest.addr][0];
                     }
                     else {
                        n = 4;
                     }
                     for (int i = 0; i < n; i++) {
                        d[i] >>= shift;
                     }
                     break;
                  }
                  case 6: {    //PSLLW mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned short *d = fpu.r[dest.addr].s;
                     if (prefix & PREFIX_SIZE) {
                        n = 8;
                        d = &sse2.xmm.w[dest.addr][0];
                     }
                     else {
                        n = 4;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 15) {
                           d[i] = 0;
                        }
                        else {
                           d[i] <<= shift;
                        }
                     }
                     break;
                  }
               }
               break;
            }
            case 2: {
               fetchOperands(&dest, &source);
               switch (dest.addr) {
                  case 2: {    //PSRLD mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned int *d = fpu.r[dest.addr].i;
                     if (prefix & PREFIX_SIZE) {
                        n = 4;
                        d = &sse2.xmm.i[dest.addr][0];
                     }
                     else {
                        n = 2;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 31) {
                           d[i] = 0;
                        }
                        else {
                           d[i] >>= shift;
                        }
                     }
                     break;
                  }
                  case 4: {    //PSRAD mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     if (shift > 31) shift = 31;
                     int *d = (int*)fpu.r[dest.addr].i;
                     if (prefix & PREFIX_SIZE) {
                        n = 4;
                        d = (int*)&sse2.xmm.i[dest.addr][0];
                     }
                     else {
                        n = 2;
                     }
                     for (int i = 0; i < n; i++) {
                        d[i] >>= shift;
                     }
                     break;
                  }
                  case 6: {    //PSLLD mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned int *d = fpu.r[dest.addr].i;
                     if (prefix & PREFIX_SIZE) {
                        n = 4;
                        d = &sse2.xmm.i[dest.addr][0];
                     }
                     else {
                        n = 2;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 31) {
                           d[i] = 0;
                        }
                        else {
                           d[i] <<= shift;
                        }
                     }
                     break;
                  }
               }
               break;
            }
            case 3: {
               fetchOperands(&dest, &source);
               switch (dest.addr) {
                  case 2: {    //PSLLD mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned long long *d = &fpu.r[dest.addr].ll;
                     if (prefix & PREFIX_SIZE) {
                        n = 2;
                        d = &sse2.xmm.ll[dest.addr][0];
                     }
                     else {
                        n = 1;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 63) {
                           d[i] = 0;
                        }
                        else {
                           d[i] >>= shift;
                        }
                     }
                     break;
                  }
                  case 3: {    //PSLRDQ xmm,imm
                     if (prefix & PREFIX_SIZE) {
                        unsigned char shift = fetchu(SIZE_BYTE);
                        if (shift > 15) shift = 16;
                        n = 16 - shift;
                        unsigned char *d = &sse2.xmm.b[dest.addr][0];
                        for (int i = 0; i < n; i++) {
                           d[i] = d[shift + i];
                        }
                        for (int i = 15; i >= n; i++) {
                           d[i] = 0;
                        }
                     }
                     break;
                  }
                  case 6: {    //PSLLD mm,imm
                     unsigned char shift = fetchu(SIZE_BYTE);
                     unsigned long long *d = &fpu.r[dest.addr].ll;
                     if (prefix & PREFIX_SIZE) {
                        n = 2;
                        d = &sse2.xmm.ll[dest.addr][0];
                     }
                     else {
                        n = 1;
                     }
                     for (int i = 0; i < n; i++) {
                        if (shift > 63) {
                           d[i] = 0;
                        }
                        else {
                           d[i] <<= shift;
                        }
                     }
                     break;
                  }
                  case 7: {    //PSLLDQ xmm,imm
                     if (prefix & PREFIX_SIZE) {
                        unsigned char shift = fetchu(SIZE_BYTE);
                        if (shift > 15) shift = 16;
                        n = 16 - shift;
                        unsigned char *d = &sse2.xmm.b[dest.addr][0];
                        for (int i = 0; i < n; i++) {
                           d[15 - i] = d[15 - shift - i];
                        }
                        for (int i = 0; i < shift; i++) {
                           d[i] = 0;
                        }
                     }
                     break;
                  }
               }
               break;
            }
            case 0xE: {  //MOVD
               fetchOperands(&source, &dest);
               opsize = SIZE_DWORD;
               if (prefix & PREFIX_SIZE) {
                  op1 = sse2.xmm.i[source.addr][0];
               }
               else {
                  op1 = fpu.r[source.addr].i[0];
               }
               storeOperand(&dest, op1);
               break;
            }
            case 0xF: {   //MOVDQA, MOVQ, MOVDQU
               fetchOperands(&source, &dest);
               if (prefix & PREFIX_SIZE || prefix & PREFIX_REP) {
                  if (dest.type == TYPE_REG) {
                     sse2.xmm.ll[dest.addr][0] = sse2.xmm.ll[source.addr][0];
                     sse2.xmm.ll[dest.addr][1] = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 16);
                  }
               }
               else {
                  if (dest.type == TYPE_REG) {
                     fpu.r[dest.addr].ll = fpu.r[source.addr].ll;
                  }
                  else {
                     writeBuffer(dest.addr, &fpu.r[source.addr].i[0], 8);
                  }
               }
               break;
            }
         }
         break;
      case 8: //Jcc
         return doSeven(); //one unsigned char Jcc handler
      case 9: //SET
         return doSet(lower);
      case 0xA: //IMUL, SHRD, SHLD
         switch (lower) {
            case 2: //CPUID
               do_cpuid();
               break;
            case 0x3: //BT
               doBitOp(doBitTest);
               break;
            case 4: case 5: case 0xC: case 0xD:
               dShift();
               break;
            case 0xB: //BTS
               doBitOp(doBitSet);
               break;
            case 0xF: //IMUL
               fetchOperands(&dest, &source);
               op1 = getOperand(&source);
               op2 = getOperand(&dest);
               result = op1 * op2;
               storeOperand(&dest, result);
               setEflags(result, opsize);
               break;
         }
         break;
      case 0xB:
         switch (lower) {
            case 0:  //CMPXCHG
               opsize = SIZE_BYTE;
            case 1: { //CMPXCHG
               fetchOperands(&source, &dest);
               result = getOperand(&dest);
               cmp(eax, result);
               msg("cmpxchg comparing (eax) 0x%x to (dest) 0x%x\n", eax, result);
               if (xZ) {
                  result = getOperand(&source);
                  msg("cmpxchg compare equal, setting dest = 0x%x\n", result);
                  storeOperand(&dest, result);
               }
               else {
                  msg("cmpxchg compare not equal, setting eax = 0x%x\n", result);
                  eax = result;
               }
               break;
            }
            case 3:  //BTR
               doBitOp(doBitReset);
               break;
            case 6: case 7: case 0xE: case 0xF:
               //MOVZX, MOVSX
               if ((opcode & 7) == 6) opsize = SIZE_BYTE;
               else opsize = SIZE_WORD;
               fetchOperands(&dest, &source);
               result = getOperand(&source);
               if (opcode & 8) { //MOVSX
                  if (opsize == SIZE_BYTE) result = sebd((unsigned char)result);
                  else result = sewd((unsigned short)result);
               }
               opsize = SIZE_DWORD;
               storeOperand(&dest, result);
               break;
            case 0xA:
               doBitOpGrp8();
               break;
            case 0xB:  //BTC
               doBitOp(doBitComplement);
               break;
            case 0xC: { //BSF
               fetchOperands(&dest, &source);
               int src = getOperand(&source);
               if (src == 0) {
                  SET(xZF);
               }
               else {
                  CLEAR(xZF);
                  unsigned int result = 0;
                  for (int i = 0; i < BITS[opsize]; i++) {
                     if (src & 1) {
                        storeOperand(&dest, result);
                        break;
                     }
                     src >>= 1;
                     result++;
                  }
               }
               break;
            }
            case 0xD: {  //BSR
               fetchOperands(&dest, &source);
               int src = getOperand(&source);
               if (src == 0) {
                  SET(xZF);
               }
               else {
                  CLEAR(xZF);
                  unsigned int result = BITS[opsize] - 1;
                  for (int i = 0; i < BITS[opsize]; i++) {
                     if (src & SIGN_BITS[opsize]) {
                        storeOperand(&dest, result);
                        break;
                     }
                     src <<= 1;
                     result--;
                  }
               }
               break;
            }
         }
         break;
      case 0xC:  //C8-xCF BSWAP
         if (lower >= 8) {
            result = cpu.general[opcode & 0x7];
            cpu.general[opcode & 0x7] = (result << 24) | ((result << 8) & 0xFF0000) |
                                    ((result >> 24) & 0xFF) | ((result >> 8) & 0xFF00);
         }
         else {
            switch (lower) {
               case 0:     //XADD
                  opsize = SIZE_BYTE;
               case 1: {    //XADD
                  fetchOperands(&source, &dest);
                  unsigned int op1 = getOperand(&dest);
                  unsigned int op2 = getOperand(&source);
                  result = add(op1, op2);
                  storeOperand(&dest, result);
                  storeOperand(&source, op1);
                  break;
               }
               case 2:    //CMPPS
                  break;
               case 3:    //MOVNTI
                  fetchOperands(&source, &dest);
                  opsize = SIZE_WORD;
                  storeOperand(&dest, getOperand(&source));
                  break;
               case 4:  {  //PINSRW
                  fetchOperands(&dest, &source);
                  opsize = SIZE_WORD;
                  unsigned char idx = fetchu(SIZE_BYTE);
                  unsigned short *d;
                  if (dest.type == TYPE_REG) {
                     if (prefix & PREFIX_SIZE) {
                        d = &sse2.xmm.w[dest.addr][0];
                        idx &= 7;
                     }
                     else {
                        d = fpu.r[dest.addr].s;
                        idx &= 3;
                     }
                     d[idx] = getOperand(&source);
                  }
//                  d[idx] = getOperand(&source);   //???
                  break;
               }
               case 5: {   //PEXTRW
                  fetchOperands(&dest, &source);
                  opsize = SIZE_DWORD;
                  unsigned char idx = fetchu(SIZE_BYTE);
                  unsigned short *s = NULL;
                  if (source.type == TYPE_REG) {
                     if (prefix & PREFIX_SIZE) {
                        s = &sse2.xmm.w[source.addr][0];
                        idx &= 7;
                     }
                     else {
                        s = fpu.r[source.addr].s;
                        idx &= 3;
                     }
                  }
                  storeOperand(&dest, s[idx]);
                  break;
               }
               case 6:    //SHUFPS
                  break;
               case 7:    //Group 9 1A
                  break;
            }
         }
         break;
      case 0xD:
         switch (lower) {
            case 0:
               break;
            case 1: {    //PSRLW
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 15) {
                     d[i] = 0;
                  }
                  else {
                     d[i] >>= shift;
                  }
               }
               break;
            }
            case 2: {   //PSRLD
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 31) {
                     d[i] = 0;
                  }
                  else {
                     d[i] >>= shift;
                  }
               }
               break;
            }
            case 3: {   //PSRLQ
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned long long *d = &fpu.r[dest.addr].ll;
               if (prefix & PREFIX_SIZE) {
                  n = 2;
                  d = &sse2.xmm.ll[dest.addr][0];
               }
               else {
                  n = 1;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 63) {
                     d[i] = 0;
                  }
                  else {
                     d[i] >>= shift;
                  }
               }
               break;
            }
            case 4: {   //PADDQ
               fetchOperands(&dest, &source);
               unsigned long long v;
//               unsigned int *vp = (unsigned int*)&v;
               if (source.type != TYPE_REG) {   //memory source, use at least 64 bits
                  readBuffer(source.addr, &v, 8);
               }
               if (prefix & PREFIX_SIZE) {       //xmm
                  if (source.type == TYPE_REG) {
                     v = sse2.xmm.ll[source.addr][0];
                  }
                  sse2.xmm.ll[dest.addr][0] += v;
                  if (source.type == TYPE_REG) {
                     v = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     readBuffer(source.addr + 8, &v, 8);
                  }
                  sse2.xmm.ll[dest.addr][1] += v;
               }
               else {
                  if (source.type == TYPE_REG) {
                     v = fpu.r[source.addr].ll;
                  }
                  fpu.r[dest.addr].ll += v;
               }
               break;
            }
            case 5:    //PMULLW
               break;
            case 6: {   //MOVDQ2Q
               fetchOperands(&dest, &source);
               if (prefix & PREFIX_REPNE) {
                  fpu.r[dest.addr].ll = sse2.xmm.ll[source.addr][0];
               }
               else if (prefix & PREFIX_REP) {
                  sse2.xmm.ll[dest.addr][0] = fpu.r[source.addr].ll;
                  sse2.xmm.ll[dest.addr][1] = 0;
               }
               break;
            }
            case 7:    //PMOVMSKB
               break;
            case 8: {   //PSUBUSB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i, SIZE_BYTE);
                  }
                  unsigned short r = d[i] - v;
                  if (r & 0x8000) {
                     r = 0;
                  }
                  d[i] = (unsigned char)r;
               }
               break;
            }
            case 9: {    //PSUBUSW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  unsigned int r = d[i] - v;
                  if (r & 0x80000000) {
                     r = 0;
                  }
                  d[i] = r;
               }
               break;
            }
            case 0xA: {   //PMINUB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i, SIZE_BYTE);
                  }
                  if (v < d[i]) {
                     d[i] = v;
                  }
               }
               break;
            }
            case 0xB: {   //PAND
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] &= v;
               }
               break;
            }
            case 0xC: {   //PADDUSB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i, SIZE_BYTE);
                  }
                  unsigned short r = d[i] + v;
                  if (r & 0x100) {
                     r = 0xFF;
                  }
                  d[i] = (unsigned char)r;
               }
               break;
            }
            case 0xD: {   //PADDUSW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  unsigned int r = d[i] + v;
                  if (r & 0x10000) {
                     r = 0xFFFF;
                  }
                  d[i] = r;
               }
               break;
            }
            case 0xE: {   //PMAXUB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i, SIZE_BYTE);
                  }
                  if (v > d[i]) {
                     d[i] = v;
                  }
               }
               break;
            }
            case 0xF: {   //PANDN
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] = ~d[i] & v;
               }
               break;
            }
         }
         break;
      case 0xE:
         switch (lower) {
            case 0:  {    //PAVGB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i, SIZE_BYTE);
                  }
                  unsigned short r = (d[i] + v + 1) >> 1;
                  d[i] = (unsigned char)r;
               }
               break;
            }
            case 1: {    //PSRAW
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               short *d = (short*)fpu.r[dest.addr].s;
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = (short*)&sse2.xmm.w[dest.addr][0];
               }
               else {
                  n = 4;
               }
               if (shift > 15) {
                  shift = 15;
               }
               for (int i = 0; i < n; i++) {
                  d[i] >>= shift;
               }
               break;
            }
            case 2: {   //PSRAD
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               int *d = (int*)fpu.r[dest.addr].i;
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = (int*)&sse2.xmm.w[dest.addr][0];
               }
               else {
                  n = 2;
               }
               if (shift > 31) {
                  shift = 31;
               }
               for (int i = 0; i < n; i++) {
                  d[i] >>= shift;
               }
               break;
            }
            case 3: {   //PAVGW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  unsigned int r = (d[i] + v + 1) >> 1;
                  d[i] = (unsigned short)r;
               }
               break;
            }
            case 4:    //PMULHUW
               break;
            case 5:    //PMULHW
               break;
            case 6:    //CVTPD2DQ
               break;
            case 7: {
               fetchOperands(&source, &dest);
               if (prefix & PREFIX_SIZE) {    //MOVNTDQ
                  writeBuffer(dest.addr, &sse2.xmm.i[source.addr][0], 16);
               }
               else {     //MOVNTQ
                  writeBuffer(dest.addr, &fpu.r[source.addr].i[0], 8);
               }
               break;
            }
            case 8: {   //PSUBSB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i, SIZE_BYTE);
                  }
                  unsigned short r = d[i] - v;
                  if (hasSubOverflow(d[i], v, r)) {
                     if (r & 0x8000) {
                        r = 0x7F;
                     }
                     else {
                        r = 0x80;
                     }
                  }
                  d[i] = (unsigned char)r;
               }
               break;
            }
            case 9: {    //PSUBSW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  unsigned int r = d[i] - v;
                  if (hasSubOverflow(d[i], v, r)) {
                     if (r & 0x80000000) {
                        r = 0x7FFF;
                     }
                     else {
                        r = 0x8000;
                     }
                  }
                  d[i] = r;
               }
               break;
            }
            case 0xA: {   //PMINSW
               fetchOperands(&dest, &source);
               short *d = (short*)fpu.r[dest.addr].s;
               short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = (short*)fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = (short*)&sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = (short*)&sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  if (v < d[i]) {
                     d[i] = v;
                  }
               }
               break;
            }
            case 0xB: {    //POR
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] |= v;
               }
               break;
            }
            case 0xC: {   //PADDSB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i, SIZE_BYTE);
                  }
                  unsigned short r = d[i] + v;
                  if (hasAddOverflow(d[i], v, r)) {
                     if (r & 0x100) {
                        r = 0x80;
                     }
                     else {
                        r = 0x7F;
                     }
                  }
                  d[i] = (unsigned char)r;
               }
               break;
            }
            case 0xD: {   //PADDSW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  unsigned int r = d[i] + v;
                  if (hasAddOverflow(d[i], v, r)) {
                     if (r & 0x10000) {
                        r = 0x8000;
                     }
                     else {
                        r = 0x7FFF;
                     }
                  }
                  d[i] = r;
               }
               break;
            }
            case 0xE: {   //PMAXSW
               fetchOperands(&dest, &source);
               short *d = (short*)fpu.r[dest.addr].s;
               short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = (short*)fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = (short*)&sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = (short*)&sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  if (v > d[i]) {
                     d[i] = v;
                  }
               }
               break;
            }
            case 0xF: {  //PXOR
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] ^= v;
               }
               break;
            }
         }
         break;
      case 0xF:
         switch (lower) {
            case 0:
               break;
            case 1: {    //PSLLW
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 15) {
                     d[i] = 0;
                  }
                  else {
                     d[i] <<= shift;
                  }
               }
               break;
            }
            case 2: {   //PSLLD
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 31) {
                     d[i] = 0;
                  }
                  else {
                     d[i] <<= shift;
                  }
               }
               break;
            }
            case 3: {   //PSLLQ
               fetchOperands(&dest, &source);
               unsigned int shift = getLongShiftCount(&dest, &source);
               unsigned long long *d = &fpu.r[dest.addr].ll;
               if (prefix & PREFIX_SIZE) {
                  n = 2;
                  d = &sse2.xmm.ll[dest.addr][0];
               }
               else {
                  n = 1;
               }
               for (int i = 0; i < n; i++) {
                  if (shift > 63) {
                     d[i] = 0;
                  }
                  else {
                     d[i] <<= shift;
                  }
               }
               break;
            }
            case 4:    //PMULUDQ
               break;
            case 5:    //PMADDWD
               break;
            case 6:    //PSADBW
               break;
            case 7:    //MASKMOVQ
               break;
            case 8: {   //PSUBB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i, SIZE_BYTE);
                  }
                  d[i] -= v;
               }
               break;
            }
            case 9: {    //PSUBW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  d[i] -= v;
               }
               break;
            }
            case 0xA: {   //PSUBD
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < 2; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] -= v;
               }
               break;
            }
            case 0xB: {   //PSUBQ
               fetchOperands(&dest, &source);
               unsigned long long v;
//               unsigned int *vp = (unsigned int*)&v;
               if (source.type != TYPE_REG) {   //memory source, use at least 64 bits
                  readBuffer(source.addr, &v, 8);
               }
               if (prefix & PREFIX_SIZE) {       //xmm
                  if (source.type == TYPE_REG) {
                     v = sse2.xmm.ll[source.addr][0];
                  }
                  sse2.xmm.ll[dest.addr][0] -= v;
                  if (source.type == TYPE_REG) {
                     v = sse2.xmm.ll[source.addr][1];
                  }
                  else {
                     readBuffer(source.addr + 8, &v, 8);
                  }
                  sse2.xmm.ll[dest.addr][1] -= v;
               }
               else {
                  if (source.type == TYPE_REG) {
                     v = fpu.r[source.addr].ll;
                  }
                  fpu.r[dest.addr].ll -= v;
               }
               break;
            }
            case 0xC: {   //PADDB
               fetchOperands(&dest, &source);
               unsigned char *d = fpu.r[dest.addr].b;
               unsigned char *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].b;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 16;
                  d = &sse2.xmm.b[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.b[source.addr][0];
                  }
               }
               else {
                  n = 8;
               }
               for (int i = 0; i < n; i++) {
                  unsigned char v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned char)readMem(source.addr + i, SIZE_BYTE);
                  }
                  d[i] += v;
               }
               break;
            }
            case 0xD: {   //PADDW
               fetchOperands(&dest, &source);
               unsigned short *d = fpu.r[dest.addr].s;
               unsigned short *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].s;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 8;
                  d = &sse2.xmm.w[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.w[source.addr][0];
                  }
               }
               else {
                  n = 4;
               }
               for (int i = 0; i < n; i++) {
                  unsigned short v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned short)readMem(source.addr + i * 2, SIZE_WORD);
                  }
                  d[i] += v;
               }
               break;
            }
            case 0xE: {   //PADDD
               fetchOperands(&dest, &source);
               unsigned int *d = fpu.r[dest.addr].i;
               unsigned int *s = NULL;
               if (source.type == TYPE_REG) {
                  s = fpu.r[source.addr].i;
               }
               if (prefix & PREFIX_SIZE) {
                  n = 4;
                  d = &sse2.xmm.i[dest.addr][0];
                  if (source.type == TYPE_REG) {
                     s = &sse2.xmm.i[source.addr][0];
                  }
               }
               else {
                  n = 2;
               }
               for (int i = 0; i < 2; i++) {
                  unsigned int v;
                  if (source.type == TYPE_REG) {
                     v = s[i];
                  }
                  else {
                     v = (unsigned int)readMem(source.addr + i * 4, SIZE_DWORD);
                  }
                  d[i] += v;
               }
               break;
            }
            case 0xF:
               break;
         }
         break;
   }
   return 1;
}

static operand_func table_0[16] = {
   doZero, doOne, doTwo, doThree, doFour, doFive, doSix, doSeven,
   doEight, doNine, doTen, doEleven, doTwelve, doThirteen, doFourteen, doFifteen
};

int executeInstruction() {
   int done = 0;
   int doTrap = cpu.eflags & xTF;
   dest.addr = source.addr = prefix = 0;
   opsize = SIZE_DWORD;  //default
   segmentBase = csBase;
   instStart = csBase + cpu.eip;
   cpu.initial_eip = cpu.eip;
//   msg("Start of instruction: %x\n", cpu.eip);
   if (doTrace) {
      traceLog("0x%08x:  ", instStart);
#if IDA_SDK_VERSION >= 700
      qstring lbuf;
      if (generate_disasm_line(&lbuf, instStart, GENDSM_FORCE_CODE)) {
         tag_remove(&lbuf, lbuf);
         traceLog("%s\n", lbuf.c_str());
      }
#else
      char lbuf[1024];
      if (generate_disasm_line(instStart, lbuf, sizeof(lbuf), GENDSM_FORCE_CODE)) {
         tag_remove(lbuf, lbuf, sizeof(lbuf));
         traceLog("%s\n", lbuf);
      }
#endif
      else {
         traceLog("\n");
      }
   }
   //test breakpoint conditions here
   if (dr7 & 0x155) {  //minimal Dr enabled
      if (((dr7 & 1) && (cpu.eip == dr0)) ||
          ((dr7 & 4) && (cpu.eip == dr1)) ||
          ((dr7 & 0x10) && (cpu.eip == dr2)) ||
          ((dr7 & 0x40) && (cpu.eip == dr3))) {
          msg("hardware breakpoint at 0x%x\n", cpu.eip);
          initiateInterrupt(1, cpu.initial_eip);
         //return from here with updated eip as a result of jumping to exception handler
         //otherwise if we fall through first instruction in exception handler gets executed.
         return 0;
      }
   }
   makeImport = cpu.eip == importSavePoint;
//msg("x86emu: begin instruction, eip: 0x%x\n", eip);
   if (isModuleAddress(cpu.eip)) {
      //eip is pointing into a dll.  Treat as a direct jump
      //to a dll function with return address already on the stack
      unsigned int nextAddr = pop(SIZE_DWORD);
      doCall(cpu.eip);
      cpu.eip = nextAddr;
   }
   else {
      try {
         while (!done) {
            fpuStart = cpu.eip;
            opcode = fetchu(SIZE_BYTE);
            if ((opcode & 0xF0) == 0x70) {
               opsize = SIZE_BYTE;
            }
            done = (*table_0[(opcode >> 4) & 0x0F])();
         }
      } catch (int exc) {
         initiateInterrupt(exc, cpu.initial_eip);       
      }
   }
   tsc.ll += 5;
   if (doTrap) {  //trace flag set
      cpu.eflags &= ~xTF;   //clear TRAP flag
      msg("trace flag set at 0x%x\n", cpu.eip);
      initiateInterrupt(1, cpu.eip);
   }
//msg("x86emu: end instruction, eip: 0x%x\n", eip);
   return 0;
}

/*
int main() {
   inst i;
   executeInstruction(&i);
   fprintf(stderr, "eax = %X\n", eax);
   return 0;
}
*/
