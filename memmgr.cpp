/*
   Source for x86 emulator IdaPro plugin
   File: memmgr.cpp
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

#define NO_OBSOLETE_FUNCS

#include <ida.hpp>
#include <idp.hpp>
#if IDA_SDK_VERSION >= 700
#include <segregs.hpp>
#else
#include <srarea.hpp>
#endif
#include <segment.hpp>

#include <stdint.h>

#include "memmgr.h"
#include "peutils.h"
#include "sdk_versions.h"

//lifted from intel.hpp
#define R_fs 33

#if IDA_SDK_VERSION < 500
#define SEGDEL_KEEP 0
#define SEGDEL_SILENT 1
#define SEGDEL_PERM 1
#endif

#if IDA_SDK_VERSION < 530
#define SEGMOD_SILENT SEGDEL_SILENT
#define SEGMOD_KEEP SEGDEL_KEEP
#define SEGMOD_KILL SEGDEL_PERM
#else
#define SEGDEL_KEEP SEGMOD_KEEP
#define SEGDEL_SILENT SEGMOD_SILENT
#endif

#define SEG_RESERVE 200

static bool haveTEB = false;
static sel_t tebSel = 0;

void createNewSegment(const char *name, uint32_t base, uint32_t size) {
//msg("createNewSegment: %s\n", name);
   //create the new segment
   segment_t s;
   memset(&s, 0, sizeof(s));
   if (strcmp(name, ".teb") == 0) {
      haveTEB = true;
      tebSel = s.sel = allocate_selector(base >> 4);
#if IDA_SDK_VERSION >= 650
      set_default_segreg_value(NULL, R_fs, s.sel);
#else
      SetDefaultRegisterValue(NULL, R_fs, s.sel);
#endif
   }
   s.startEA = base;
   s.endEA = base + size;
   s.align = saRelPara;
   s.comb = scPub;
   s.perm = SEGPERM_WRITE | SEGPERM_READ | SEGPERM_EXEC;
   s.bitness = 1;   //== 32
   s.type = SEG_CODE;
   s.color = DEFCOLOR;
   
//   if (add_segm_ex(&s, name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
   if (add_segm_ex(&s, name, "CODE", ADDSEG_QUIET | ADDSEG_NOSREG)) {
      //zero out the newly created segment
      zero_fill(base, size);
      if (haveTEB) {
#if IDA_SDK_VERSION >= 650
         set_default_segreg_value(&s, R_fs, tebSel);
#else
         SetDefaultRegisterValue(&s, R_fs, tebSel);
#endif
      }
   }
}

void createOverlaySegment(const char *name, uint32_t base, uint32_t size) {
   //create the new segment
   segment_t *current = getseg(base);
   if (current == NULL) {
      //not an overlay
      return;
   }
   segment_t s = *current;
   s.startEA = base;
   s.endEA = base + size;
   //all other attributes come from existing segment
   
//   if (add_segm_ex(&s, name, "DATA", ADDSEG_QUIET | ADDSEG_NOSREG)) {
   add_segm_ex(&s, name, "CODE", ADDSEG_QUIET | ADDSEG_NOSREG);
}

segment_t *next_seg(ea_t addr) {
#if IDA_SDK_VERSION >= 530
   return get_next_seg(addr);
#else
   int snum = segs.get_next_area(addr);
   if (snum == -1) {
      return NULL;
   }
   else {
      return getnseg(snum);
   }
#endif
}

segment_t *prev_seg(ea_t addr) {
#if IDA_SDK_VERSION >= 530
   return get_prev_seg(addr);
#else
   int snum = segs.get_prev_area(addr);
   if (snum == -1) {
      return NULL;
   }
   else {
      return getnseg(snum);
   }
#endif
}

/*
static const char memmgr_node_name[] = "$ X86emu memory manager";

//The IDA database node identifier into which the plug-in will
//store its state information when the database is saved.
static netnode memmgr_node(x86emu_node_name);

MemMgr::MemMgr() {
   if (netnode_exist(memmgr_node)) {
   }
   else {
      memmgr_node.create(memmgr_node_name);
   }
}
*/

void MemMgr::reserve(uint32_t addr, uint32_t size) {
   segment_t *s = getseg(addr);
   if (s) {
      size = (size + 0xFFF) & 0xFFFFF000;
      uint32_t end = addr + size;
      if (end > s->endEA) {
         segment_t *n = next_seg(addr);
         if (n) {
            if (n->startEA <= end) {
               //no room so fail
               return;
            }
         }
         else {
            if (end < s->startEA) {
               //end wrapped around so fail
               return;
            }
         }
         netnode segnode(s->startEA);
         segnode.altset(SEG_RESERVE, end, 'Z');
      }
   }
}

uint32_t MemMgr::mapFixed(uint32_t addr, uint32_t size, uint32_t /*prot*/, uint32_t flags, const char *name) {
   if (addr == 0 || (flags & MM_MAP_FIXED) == 0) {
      return (uint32_t)BADADDR;
   }
   uint32_t end = addr + size;
   segment_t *s = getseg(addr);
   segment_t *n = next_seg(addr);

   while (n && end >= n->endEA) {
      //range completely consumes next segment
      del_segm(n->startEA, SEGDEL_KEEP | SEGDEL_SILENT);
      n = next_seg(addr);
   }
   if (n && end > n->startEA) {
      //range partly overlaps next segment
      set_segm_start(n->startEA, end, SEGMOD_SILENT);
   }

   if (s) {
      if (s->startEA < addr) {
         //may need to split segment
         //addr == s->startEA
         if (end >= s->endEA) {
            //new extends beyond end of s
            set_segm_end(s->startEA, addr, SEGMOD_SILENT);
         }
         else {
            //old completely overlaps new
         }
      }
      else {
         //addr == s->startEA
         if (end >= s->endEA) {
            //new completely overlaps s
            del_segm(s->startEA, SEGDEL_KEEP | SEGDEL_SILENT);
         }
         else {
            //need to move startEA
            set_segm_start(s->startEA, end, SEGMOD_SILENT);
         }
      }
   }
   
   uint32_t suffix = (addr >> 12) & 0xFFFFF;
   if (name == NULL) {
      char segName[64];
      ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
      createNewSegment(segName, addr, size);
   }
   else {
      createNewSegment(name, addr, size);
   }
   return addr;
}

//search up from bottom for block of size
uint32_t MemMgr::search_up(uint32_t bottom, uint32_t size, uint32_t top) {
   size = (size + 0xfff) & 0xfffff000;
   top = top & 0xfffff000;
   uint32_t addr = (bottom + 0xfff) & 0xfffff000;
   uint32_t max_low_addr = top - size;
   if (max_low_addr > top || max_low_addr < bottom) {
      //ENOMEM
      return (uint32_t)BADADDR;
   } 
   while (addr <= max_low_addr) {
      //is there already a segment here?
      segment_t *s = getseg(addr);
      if (s == NULL) {            
         //find next segment to compute any gap
         segment_t *n = next_seg(addr);
         uint32_t avail = 0;
         if (n) {
            //if there is a next seg we are bounded by its lower limit
            uint32_t effectiveStart = (uint32_t)s->startEA & 0xfffff000;
            avail = effectiveStart - addr;
         }
         else {
            avail = top - addr;
         }
         if (avail >= size) {
            return addr;
         }
         if (n == NULL) {
            return (uint32_t)BADADDR;
         }
         s = n;
      }
      //move up to page rounded end of next seg and try again
      addr = (0xFFF + (uint32_t)s->endEA) & 0xFFFFF000;
   }
   return (uint32_t)BADADDR;
}

//search down from top for block of size
uint32_t MemMgr::search_down(uint32_t top, uint32_t size, uint32_t bottom) {
   size = (size + 0xfff) & 0xfffff000;
   uint32_t min_high_addr = bottom + size;
   if (min_high_addr > top || min_high_addr < bottom) {
      //ENOMEM
      return (uint32_t)BADADDR;
   }
   uint32_t addr = top & 0xfffff000;
   while (addr >= min_high_addr) {
      //is there already a segment here?
      segment_t *s = getseg(addr);
      if (s) {
         //if so drop down to page rounded start of seg
         addr = s->startEA & 0xFFFFF000;
      }
      //find previous segment to compute any gap
      segment_t *p = prev_seg(addr);
      uint32_t avail = 0;
      if (p) {
         //if there is a prev seg we are bounded by its upper limit
         uint32_t effectiveEnd = (0xfff + (uint32_t)p->endEA) & 0xfffff000;
         avail = addr - effectiveEnd;
      }
      else {
         //if there is no previous seg we are bounded by "limit"
         avail = addr - bottom;
      }
      if (avail >= size) {
         return addr - size;
      }
      if (p == NULL) {
         //fail because we were bounded by lower limit and avail was too small
         return (uint32_t)BADADDR;
      }
      //drop down to page rounded start of prev seg and try again
      addr = p->startEA & 0xFFFFF000;
   }
   return (uint32_t)BADADDR;
}

//addr must be page aligned
uint32_t MemMgr::mmap(uint32_t addr, uint32_t size, uint32_t prot, uint32_t flags, const char *name) {
   if (flags & MM_MAP_FIXED) {
      return mapFixed(addr, size, prot, flags, name);
   }
   uint32_t growth = (uint32_t)kernel_node.altval(OS_VMA_GROWTH);
   //uint32_t page_size = (uint32_t)kernel_node.altval(OS_PAGE_SIZE);
   //uint32_t page_mask = ~(page_size - 1);
   uint32_t upper_limit = (uint32_t)kernel_node.altval(OS_VMA_HIGH);
   uint32_t lower_limit = (uint32_t)kernel_node.altval(OS_VMA_LOW);
   if (addr) {
      //addr is a hint in this case
      //always try search up w/ addr as lower limit then fall back below
      addr = search_up(addr, size, upper_limit);
      if (addr == BADADDR) {
         addr = 0; //forces fallback below
      }
   }
   if (addr == 0) {
      if (growth == OS_VMA_GROWS_DOWN) {
         addr = search_down(upper_limit, size, lower_limit);
      }
      else {
         addr = search_up(lower_limit, size, upper_limit);
      }
   }
   if (addr != BADADDR) {
      uint32_t suffix = (addr >> 12) & 0xFFFFF;
      if (name == NULL) {
         char segName[64];
         ::qsnprintf(segName, sizeof(segName), "mmap_%05x", suffix);
         createNewSegment(segName, addr, size);
      }
      else {
         createNewSegment(name, addr, size);
      }
   }
   return addr;
}

uint32_t MemMgr::munmap(uint32_t addr, uint32_t size, bool keep) {
   addr &= 0xFFFFF000;   //unmap from page boundary
   size = (size + 0xFFF) & 0xFFFFF000;
   uint32_t end = addr + size;
   for (segment_t *s = getseg(addr); addr < end; s = getseg(addr)) {
      uint32_t segend = (uint32_t)s->endEA;
      if (s == NULL) {
#if IDA_SDK_VERSION < 530
         s = (segment_t *)segs.getn_area(segs.get_next_area(addr));
#else
         s = get_next_seg(addr);
#endif
         addr = s ? (uint32_t)s->startEA : end;
         continue;
      }
      if (addr != s->startEA) {
         //need to truncate or split segment
         if (end < segend) {
            char segname[64];
            qsnprintf(segname, sizeof(segname), "mmap_%x", end >> 12);
            createOverlaySegment(segname, end, segend - end);
         }
         set_segm_end(s->startEA, addr, keep ? SEGMOD_KEEP : SEGMOD_KILL);
      }
      else {
         //delete whole or only first part of segment
         if (end < segend) {
            set_segm_start(s->startEA, end, keep ? SEGMOD_KEEP : SEGMOD_KILL);
         }
         else {
            del_segm(addr, keep ? SEGMOD_KEEP : SEGMOD_KILL);
         }
      }
      addr = segend;
   }
   return 0;
}

