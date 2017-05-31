/*
   Source for x86 emulator IdaPro plugin
   File: seh.h
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

#ifndef __WIN_SEH_H
#define __WIN_SEH_H

#include "context.h"
#include "buffer.h"

#define SEH_MAGIC 0xBABEFACE
#define VEH_MAGIC 0xFACEBABE

#define SIZEOF_387_REGS      80
#define MAXIMUM_EXTENSION    512

//Some exception codes

//Read or write memory violation
#define MEM_ACCESS 0xC0000005   

//Illegal instruction
#define UNDEFINED_OPCODE_EXCEPTION 0xC000001D   

//Divide by zero
#define DIV_ZERO_EXCEPTION 0xC0000094   

//Divide overflow
#define DIV_OFLOW 0xC0000095   

//The stack went beyond the maximum available size
#define STACK_OVERFLOW 0xC00000FD   

//Violation of a guard page in memory set up using Virtual Alloc
#define GUARD_ERROR 0x80000001   

//The following only occur whilst dealing with exceptions:-

//A non-continuable exception: the handler should not try to deal with it
#define NON_CONT 0xC0000025    

//Exception code used the by system during exception handling. This code might
//be used if the system encounters an unexpected return from a handler. It is
//also used if no Exception Record is supplied when calling RtlUnwind.
#define EXC_EXC 0xC0000026   

//The following are used in debugging:-

//Breakpoint occurred because there was an INT3 in the code
#define BREAKPOINT_EXCEPTION 0x80000003   

//Single step during debugging
#define DEBUG_EXCEPTION 0x80000004   

#define CONTINUABLE 0
#define NON_CONTINUABLE 1
#define STACK_UNWINDING 2

#define EXCEPTION_CONTINUE_EXECUTION 0xffffffff
#define EXCEPTION_CONTINUE_SEARCH 0

#define MAXIMUM_PARMS 15

struct EXCEPTION_RECORD {
   unsigned int exceptionCode;
   unsigned int exceptionFlags;
   unsigned int exceptionRecord;  //struct _EXCEPTION_RECORD *ExceptionRecord
   unsigned int exceptionAddress;
   unsigned int numberParameters;
   unsigned int exceptionInformation[MAXIMUM_PARMS];
};

struct EXCEPTION_POINTERS {
   EXCEPTION_RECORD *exceptionRecord;
   WIN_CONTEXT *contextRecord;
};

struct ERR {
   unsigned int nextErr;  //struct _ERR *nextErr;
   unsigned int handler;  //pointer to handler
};   

int usingSEH();
void sehBegin(unsigned int interrupt_number);
void sehReturn();
void vehReturn();
void breakpointException();
void debugException();
void divzeroException();
void memoryAccessException();
void enableSEH();
void saveSEHState(Buffer &b);
void loadSEHState(Buffer &b);
void saveVEHState(Buffer &b);
void loadVEHState(Buffer &b);
struct WIN_CONTEXT *getContext();

void addVectoredExceptionHandler(bool first, unsigned int handler);
void removeVectoredExceptionHandler(unsigned int handler);

#endif
