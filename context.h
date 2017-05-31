/*
   Source for x86 emulator IdaPro plugin
   File: context.h
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

#ifndef __WIN_CONTEXT_H
#define __WIN_CONTEXT_H

#define SIZEOF_387_REGS      80
#define MAXIMUM_EXTENSION    512

struct WIN_FLOATING_SAVE_AREA {
   unsigned int   ControlWord;
   unsigned int   StatusWord;
   unsigned int   TagWord;
   unsigned int   ErrorOffset;
   unsigned int   ErrorSelector;
   unsigned int   DataOffset;
   unsigned int   DataSelector;
   unsigned char    RegisterArea[SIZEOF_387_REGS];
   unsigned int   Cr0NpxState;
};

struct WIN_CONTEXT {

   unsigned int ContextFlags;

   unsigned int   Dr0;
   unsigned int   Dr1;
   unsigned int   Dr2;
   unsigned int   Dr3;
   unsigned int   Dr6;
   unsigned int   Dr7;

   WIN_FLOATING_SAVE_AREA FloatSave;

   unsigned int   SegGs;
   unsigned int   SegFs;
   unsigned int   SegEs;
   unsigned int   SegDs;

   unsigned int   Edi;   //0x9C
   unsigned int   Esi;   //0xA0
   unsigned int   Ebx;   //0xA4
   unsigned int   Edx;   //0xA8
   unsigned int   Ecx;   //0xAC
   unsigned int   Eax;   //0xB0

   unsigned int   Ebp;   //0xB4
   unsigned int   Eip;   //0xB8
   unsigned int   SegCs;
   unsigned int   EFlags;
   unsigned int   Esp;
   unsigned int   SegSs;

   unsigned char   ExtendedRegisters[MAXIMUM_EXTENSION];

};

void regsToContext(Registers *regs, WIN_CONTEXT *ctx);
void contextToRegs(WIN_CONTEXT *ctx, Registers *regs);
void initContext(WIN_CONTEXT *ctx);
void copyContextToMem(WIN_CONTEXT *ctx, unsigned int addr);


#endif
