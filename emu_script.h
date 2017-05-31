/*
   Scripting support for the x86 emulator IdaPro plugin
   Copyright (c) 2008-2010 Chris Eagle
   
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

#ifndef __EMU_SCRIPT_H
#define __EMU_SCRIPT_H

/* add IDC functions for interacting with the emulator
  EmuRun();
  EmuTrace();
  EmuStepOne();
  EmuTraceOne();
  EmuSync();
  EmuGetReg(regno);
  EmuSetReg(regno, value);
  EmuAddBpt(addr);
*/

#define EAX_REG 0
#define ECX_REG 1
#define EDX_REG 2
#define EBX_REG 3
#define ESP_REG 4
#define EBP_REG 5
#define ESI_REG 6
#define EDI_REG 7

#define EIP_REG 8
#define EFLAGS_REG 9

#define CS_REG 10
#define SS_REG 11
#define DS_REG 12
#define ES_REG 13
#define FS_REG 14
#define GS_REG 15

#define CS_BASE 20
#define SS_BASE 21
#define DS_BASE 22
#define ES_BASE 23
#define FS_BASE 24
#define GS_BASE 25

#define CR0_REG 30
#define CR1_REG 31
#define CR2_REG 32
#define CR3_REG 33
#define CR4_REG 34

#define DR0_REG 40
#define DR1_REG 41
#define DR2_REG 42
#define DR3_REG 43
#define DR4_REG 44
#define DR5_REG 45
#define DR6_REG 46
#define DR7_REG 47

void register_funcs();
void unregister_funcs();

#endif
