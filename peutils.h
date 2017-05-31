/*
   Source for x86 emulator IdaPro plugin
   Copyright (c) 2005-2010 Chris Eagle
   
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

#ifndef __PE_UTILS_H
#define __PE_UTILS_H

#include <stdio.h>
#include <pro.h>

#include "buffer.h"

struct _IMAGE_NT_HEADERS;
struct _IMAGE_SECTION_HEADER;
struct _IMAGE_EXPORT_DIRECTORY;

//IMAGE_NT_HEADERS.FileHeader.Characteristics dw offset 4 + 0x12 = 0x16 = 22
//exe will have the following set
#define _IMAGE_FILE_EXECUTABLE_IMAGE 2
//dll will have the following set IN ADDITION to _IMAGE_FILE_EXECUTABLE_IMAGE
#define _IMAGE_FILE_DLL 0x2000

//IMAGE_NT_HEADERS.OptionalHeader.Subsystem dw offset 0x18 + 0x44 = 0x5C = 92
#define _IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define _IMAGE_SUBSYSTEM_WINDOWS_CUI 3

#define _DLL_PROCESS_ATTACH 1
#define _DLL_PROCESS_DETACH 0
#define _DLL_THREAD_ATTACH  2
#define _DLL_THREAD_DETACH  3

#define _SW_HIDE 0
#define _SW_MAXIMIZE 3
#define _SW_MINIMIZE 6
#define _SW_RESTORE 9
#define _SW_SHOW 5
#define _SW_SHOWMAXIMIZED 3
#define _SW_SHOWMINIMIZED 2
#define _SW_SHOWMINNOACTIVE 7
#define _SW_SHOWNA 8
#define _SW_SHOWNOACTIVATE 4
#define _SW_SHOWNORMAL 1 

struct thunk_rec {
   char *dll_name;
   unsigned int iat_base;  //base VA for iat
   unsigned int iat_size;
   unsigned int *iat;
//   char **names;
   thunk_rec *next;
};

class PETables {
public:
   PETables();
   ~PETables();
   unsigned int rvaToFileOffset(unsigned int rva);
   void setBase(unsigned int b) {base = b;};
   void setNtHeaders(_IMAGE_NT_HEADERS *inth);
   void setSectionHeaders(unsigned int nsecs, _IMAGE_SECTION_HEADER *ish);
   void buildThunks(FILE *f);
   void destroy();
   void loadTables(Buffer &b);
   void saveTables(Buffer &b);
   
   unsigned int valid;
   unsigned int base;
   _IMAGE_NT_HEADERS *nt;
   _IMAGE_SECTION_HEADER *sections;
   unsigned short num_sections;
   thunk_rec *imports;
};

struct DllList {
   char *dllName;
   unsigned int handle;
   unsigned int id;
   unsigned int maxAddr;
   _IMAGE_NT_HEADERS *nt;
   _IMAGE_SECTION_HEADER *sections;
   _IMAGE_EXPORT_DIRECTORY *exportdir;
   unsigned int NoF;  //NumberOfFunctions
   unsigned int NoN;  //NumberOfNames
   unsigned int *eat; // AddressOfFunctions  export address table
   unsigned int *ent; // AddressOfNames      export name table
   unsigned short *eot;  // AddressOfNameOrdinals  export ordinal table
   DllList *next;
};

unsigned int loadIntoIdb(FILE *dll);
void applyPEHeaderTemplates(unsigned int mz_addr);
void createSegment(unsigned int start, unsigned int size, unsigned char *content, 
                   unsigned int clen = 0, const char *name = NULL);
void zero_fill(ea_t base, size_t size);

#endif
