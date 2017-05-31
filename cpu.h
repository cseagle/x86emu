/*
   Headers for x86 emulator
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

#ifndef __CPU_H
#define __CPU_H

#include "x86defs.h"

#define CPU_VERSION VERSION(1)

typedef struct _DescriptorTableReg_t {
   unsigned int base;
   unsigned short limit;
} DescriptorTableReg;

struct Registers {
   unsigned int debug_regs[8];
   unsigned int general[8];
   unsigned int initial_eip;
   unsigned int eip;
   unsigned int eflags;
   unsigned int control[5];
   unsigned int segBase[6];   //cached segment base addresses
   unsigned short segReg[6];
   DescriptorTableReg gdtr;
   DescriptorTableReg idtr;
};

extern Registers cpu;

union FpuMmxRegister {
   long double fp;
   unsigned char  b[10];   //only use 8 of these for mmx
   unsigned short s[4];
   unsigned int   i[2];
   unsigned long long ll;
};

struct FloatingPointUnit {
   FpuMmxRegister r[8];
   unsigned short control;
   unsigned short status;
   unsigned short tag;
   unsigned int lastIP;
   unsigned int lastIPseg;
   unsigned int lastDataPointer;
   unsigned int lastDataSeg;
   unsigned short opcode;
};

extern FloatingPointUnit fpu;

struct SSE2Registers {
   unsigned int mxcsr;
   union {
      unsigned char  b[8][16];
      unsigned short w[8][8];
      unsigned int   i[8][4];
      float          f[8][4];
      unsigned long long ll[8][2];
      double         d[8][2];
   } xmm;
};

extern SSE2Registers sse2;

extern ll_union tsc;

//masks to clear out bytes appropriate to the sizes above
extern unsigned int SIZE_MASKS[5];

//masks to clear out bytes appropriate to the sizes above
extern unsigned int SIGN_BITS[5];

//masks to clear out bytes appropriate to the sizes above
extern unsigned long long CARRY_BITS[5];

extern unsigned char BITS[5];

extern unsigned int importSavePoint;

extern unsigned int shouldBreak;
extern bool breakOnExceptions;

typedef struct _IntrRecord_t {
   bool hasError;
   struct _IntrRecord_t *next;
} IntrRecord;

typedef struct _AddrInfo_t {
   unsigned int addr;
   unsigned char type;
   unsigned char modrm;
} AddrInfo;

//struct to describe an instruction being decoded
typedef struct _inst {
   AddrInfo source;
   AddrInfo dest;
   unsigned int opsize;  //operand size for this instruction
   unsigned int prefix;  //any prefix flags
   unsigned char opcode;   //opcode, first or second unsigned char (if first == 0x0F)
} inst;

// Status codes returned by the database blob reading routine
enum {
   X86EMULOAD_OK,                   // state loaded ok
   X86EMULOAD_VERSION_INCOMPATIBLE, // incompatible version
   X86EMULOAD_CORRUPT,              // corrupt/truncated
   X86EMULOAD_UNKNOWN_HOOKFN,       // contains hook to unknown hook function
   X86EMULOAD_NO_NETNODE,           // no save data present
   X86EMUSAVE_OK,                   // state save success
   X86EMUSAVE_FAILED                // state save failed (buffer problems)
};

void initProgram(unsigned int entry, unsigned int idtBase, unsigned int idtLimit);
void enableSEH();

void resetCpu();

void push(unsigned int val, unsigned char size);
unsigned int pop(unsigned char size);
unsigned char readByte(unsigned int addr);
void writeByte(unsigned int addr, unsigned char val);
unsigned int readDword(unsigned int addr);
void writeDword(unsigned int addr, unsigned int val);
void writeMem(unsigned int addr, unsigned int val, unsigned char size);
unsigned int readMem(unsigned int addr, unsigned char size);

int executeInstruction();
void doInterruptReturn();

void initGDTR(unsigned int gdtBase, unsigned int gdtLimit);
unsigned int getGdtDescBase(unsigned int desc);
unsigned int getGdtDescLimit(unsigned int desc);
void setGdtDesc(unsigned int desc, unsigned int base, unsigned int limit);

typedef int (*operand_func)(void);

#ifdef __IDP__

int saveState(netnode &f);
int loadState(netnode &f);

#endif

#endif

