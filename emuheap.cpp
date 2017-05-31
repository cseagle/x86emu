/*
   Source for x86 emulator IdaPro plugin
   File: emuheap.cpp
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

#include <stdlib.h>
#include <string.h>

#ifndef _MSC_VER
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS 1
#endif
#endif

#include <ida.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>

#include "emuheap.h"
#include "memmgr.h"

#define MMAP_THRESHOLD 0x1000

HeapBase *HeapBase::primaryHeap = NULL;

//Constructor for malloc'ed node
MallocNode::MallocNode(unsigned int size, unsigned int base) {
   this->base = base;
   this->size = size;
   next = NULL;
}

MallocNode::MallocNode(Buffer &b) {
   b.read((char*)&base, sizeof(base));
   b.read((char*)&size, sizeof(size));
//   msg("x86emu:    loading malloc block(0x%x, 0x%x)\n", base, size);
}

void MallocNode::save(Buffer &b) {
   b.write((char*)&base, sizeof(base));
   b.write((char*)&size, sizeof(size));
//   msg("x86emu:    storing malloc block(0x%x, 0x%x)\n", base, size);
}

//need at least one non-inline function from HeapBase so that
//vtable will get allocated
HeapBase::~HeapBase() {
}

//Emulation heap constructor, indicate virtual address of base and max size
EmuHeap::EmuHeap(unsigned int baseAddr, unsigned int currSize, unsigned int maxSize, EmuHeap *next) {
   head = NULL;
   base = baseAddr;
   size = currSize;
   max = base + maxSize;
   nextHeap = next;
   if (primaryHeap == NULL) {
      primaryHeap = this;
   }
   large = NULL;
   numLarge = 0;
}

//Emulation heap constructor, indicate virtual address of base and max size
//creates heap from existing IDA segment
EmuHeap::EmuHeap(const char *name, unsigned int maxSize) {
   h = get_segm_by_name(name);
   head = NULL;
   base = (unsigned int)h->startEA;
   size = (unsigned int)h->endEA - base;
   max = maxSize + base;
   nextHeap = NULL;
   if (primaryHeap == NULL) {
      primaryHeap = this;
   }
   large = NULL;
   numLarge = 0;
}

EmuHeap::EmuHeap(Buffer &b, unsigned int num_blocks) {
   nextHeap = NULL;
   readHeap(b, num_blocks);
   if (primaryHeap == NULL) {
      primaryHeap = this;
   }
   large = NULL;
   numLarge = 0;
}

//Construct new heap from binary buffer data
EmuHeap::EmuHeap(Buffer &b) {
   unsigned int n;
   nextHeap = NULL;
   head = NULL;
   unsigned int num_heaps;
   b.read((char*)&num_heaps, sizeof(num_heaps));  //how many heaps
   
//   msg("Loading %d heaps\n", num_heaps);
   
   EmuHeap *p = NULL;
   for (unsigned int i = 0; i < num_heaps; i++) {
      b.read((char*)&n, sizeof(n));
//      msg("Loading heap #%d\n", i);
      if (p) {
         p->nextHeap = new EmuHeap(b, n);
         p = (EmuHeap*)p->nextHeap;
      }
      else {
         readHeap(b, n);
         p = this;
      }
   }
   large = NULL;
   numLarge = 0;
}

//read a heap consisting of num_blocks allocated blocks from a buffer
void EmuHeap::readHeap(Buffer &b, unsigned int num_blocks) {
   b.read((char*)&base, sizeof(base));
   b.read((char*)&size, sizeof(size));
   b.read((char*)&max, sizeof(max));
//   msg("x86emu: Reading heap(0x%x, 0x%x, 0x%x)\n", base, size, max);
   for (unsigned int i = 0; i < num_blocks; i++) {
      insert(new MallocNode(b));
   }
}

//dump a heap to a buffer
void EmuHeap::writeHeap(Buffer &b) {
   unsigned int n = 0;
   MallocNode *m;
   for (m = head; m; m = m->next) n++;
//   msg("x86emu: Writing heap(0x%x, 0x%x, 0x%x) with %d nodes\n", base, size, max, n);
   b.write((char*)&n, sizeof(n));
   b.write((char*)&base, sizeof(base));
   b.write((char*)&size, sizeof(size));
   b.write((char*)&max, sizeof(max));
   for (m = head; m; m = m->next) {
      m->save(b);
   }
}

//Save existing heap to binary buffer
void EmuHeap::save(Buffer &b) {
   unsigned int num_heaps = 0;
   EmuHeap *h;
   
   //count the number of heaps
   for (h = this; h; h = (EmuHeap*)h->nextHeap) num_heaps++;

   b.write((char*)&num_heaps, sizeof(num_heaps));

//   msg("x86emu: writing %d heaps\n", num_heaps);

   //write all of the heaps
   for (h = this; h; h = (EmuHeap*)h->nextHeap) {
      h->writeHeap(b);
   }  
}

//Destructor for the emulator heap
EmuHeap::~EmuHeap() {   
   if (nextHeap) {
      delete nextHeap;
   }
   MallocNode *p, *t = head;
   while (t) {
      p = t;
      t = t->next;
      delete p;
   }
}

//Emulation heap malloc function
unsigned int EmuHeap::malloc(unsigned int size) {
   unsigned int addr;
   size = (size + 3) & 0xFFFFFFFC;  //round up to word boundary
   //find a gap that we can fit in
   if (size >= MMAP_THRESHOLD) {
      //use mmap to fulfil the request
      size += (MMAP_THRESHOLD - 1);
      size &= ~(MMAP_THRESHOLD - 1);
      addr = MemMgr::mmap(0, size, 0, 0);
      size |= 1;
   }
   else {
      addr = findBlock(size);
   }
   if (addr != HEAP_ERROR) {
      //create and insert a new malloc node into the allocation list
      insert(new MallocNode(size, addr));
   }
   return addr;
}

//Emulation heap calloc function
unsigned int EmuHeap::calloc(unsigned int nmemb, unsigned int size) {
   //first malloc the block
   unsigned int total = nmemb * size;
   unsigned int addr = this->malloc(total);
   if (addr != HEAP_ERROR) {
      //find the newly malloc'ed block and zeroize it if necessary
      MallocNode *p = findMallocNode(addr);
      if ((p->size & 1) == 0) {
         //this is a smaller block so zeroize it
         for (unsigned int i = 0; i < total; i++) {
            patch_byte(addr + i, 0);
         } 
      }
   }
   return addr;
}

//emulation heap free function
unsigned int EmuHeap::free(unsigned int addr) {
   if (addr) {
      MallocNode *p = NULL, *t = head;
      //look for the matching malloc'ed block
      while (t) {
         //supplied address must be the base of a malloc'ed block
         if (t->base == addr) {
            //unlink the malloc'ed node
            if (p) {
               p->next = t->next;
            }
            else {
               head = t->next;
            }
            //free the malloc'ed memory
            if (t->size & 1) {
               //this was a large block
               MemMgr::munmap(t->base, t->size);
            }
            delete t;
            break;
         }
         p = t;
         t = t->next;
      }
      if (t == NULL) addr = 0;
   }
   return addr;
}

//emulations heap realloc function
unsigned int EmuHeap::realloc(unsigned int ptr, unsigned int size) {
   unsigned int result = HEAP_ERROR;
   if (ptr == 0) {
      //act like malloc if ptr is NULL
      result = this->malloc(size);
   }
   else {
      //find the malloc'ed node
      MallocNode *node = findMallocNode(ptr);
      //round the new size to a word boundary
      size = (size + 3) & 0xFFFFFFFC;
      if (node) {
         if (size == node->size) {
            //no change in size? do nothing
            result = ptr;
         }
         else if (size < node->size) {
            //node shrinking, shrink node size
            node->size = size;
            result = ptr;
         }
         else {
            //node growing, allocate new block
            //*** check to see if following block is free and 
            //we can just grow the existing block
            result = this->malloc(size);
            if (result != HEAP_ERROR) {
               //copy the old block into the new larger block
               for (unsigned int i = 0; i < node->size; i++) {
                  patch_byte(result + i, get_byte(ptr + i));
               }
               //free the old block
               this->free(ptr);
            }
         }
      }
   }
   return result;
}

//insert a newly malloc'ed node into the allocation list
//the list is sorted by increasing base address
void EmuHeap::insert(MallocNode *node) {
   MallocNode *p = NULL, *t = head;
   while (t && t->base < node->base) {
      p = t;
      t = t->next;
   }
   node->next = t;
   if (p) {
      p->next = node;
   }
   else {
      head = node;
   }
}

//find the malloc'ed node based at the specified address
MallocNode *EmuHeap::findMallocNode(unsigned int addr) {
   MallocNode *result = NULL;
   for (MallocNode *p = head; p; p = p->next) {
      if (p->base == addr) {
         return p;
      }
   }
   return result;
}

unsigned int EmuHeap::sizeOf(unsigned int addr) {
   MallocNode *result = findMallocNode(addr);
   return result ? (result->size & ~1) : 0xffffffff;
}

bool EmuHeap::checkHeapSize(unsigned int newsize) {
//msg("checkHeapSize: base: %x, newsize: %x, max: %x\n", base, newsize, max);
   if ((base + newsize) > max) {
      return false;
   }
   if (newsize > size) {
      //need to grow our heap segment
//      segment_t *h = getseg(base);
      unsigned int newend = (newsize + 0xFFF) & ~0xFFF;  //round up to 4k boundary
      set_segm_end(base, base + newend, 0);
   }
   return true;
}


//locate a block large enough to satisfy the caller's request
//keep a 4 byte gap between all blocks in order to detect overflows
unsigned int EmuHeap::findBlock(unsigned int bsize) {
   unsigned int result = HEAP_ERROR;
   MallocNode *p;
   //first see if we can fit in a gap between exiting blocks
   for (p = head; p && p->next; p = p->next) {
      if (p->size & 1 || p->next->size & 1) {
         //one or both are large blocks so skip
         continue;
      }
      unsigned int gap = p->next->base - (p->base + p->size);
      if ((bsize + 8) <= gap) {
         return p->base + p->size + 4;
      }
   }
   if (p) {
      //compute the start address of the block
      unsigned int nextBase = p->base + p->size + 4;
      if (checkHeapSize(nextBase + bsize - base)) {
         //success only if we are not out of memory
         result = nextBase;
      }
   }
   else { //first block goes at the base of the heap
      if (checkHeapSize(bsize)) {
         result = base;
      }
   }
   return result;
}

void HeapBase::saveHeapLayout(Buffer &b) {
   primaryHeap->save(b);
}

void EmuHeap::loadHeapLayout(Buffer &b) {
   primaryHeap = new EmuHeap(b);   
}

void EmuHeap::initHeap(const char *name, unsigned int maxSize) {
   primaryHeap = new EmuHeap(name, maxSize);
}   

unsigned int EmuHeap::getPrimaryHeap() {
   return primaryHeap->getHeapBase();
}

unsigned int HeapBase::addHeap(unsigned int maxSize, unsigned int base) {
   EmuHeap *h, *p = NULL;
   char buf[16];
   int count = 0;
   if (primaryHeap == 0) {
      MemMgr::mmap(base, maxSize, 0, MM_MAP_FIXED, ".heap");
      primaryHeap = new EmuHeap(".heap", maxSize);
      return base;
   }
   else {
      for (h = (EmuHeap*)primaryHeap; h; h = (EmuHeap*)h->nextHeap) {
         p = h;
         count++;
      }
      if (p) {
         ::qsnprintf(buf, 16, ".heap%d", count);
         MemMgr::mmap(p->max, 0x1000, 0, MM_MAP_FIXED, buf);
         //really need to check maxSize + max here against 0xFFFFFFFF
         p->nextHeap = new EmuHeap(p->max, 0x1000, maxSize);
      }
      return p ? p->max : 0;
   }
}

unsigned int EmuHeap::destroyHeap(unsigned int handle) {
   EmuHeap *h, *p = NULL;
   for (h = (EmuHeap*)primaryHeap; h; h = (EmuHeap*)h->nextHeap) {
      if (h->base == handle) break;
      p = h;
   }
   if (p && h) {  //prevents deletion of primaryHeap
      p->nextHeap = h->nextHeap;
      h->nextHeap = NULL;
#ifdef SEGDEL_PERM      
      del_segm(h->base, SEGDEL_PERM | SEGDEL_SILENT);
#else
      del_segm(h->base, 1);
#endif
      delete h;
      return 1;
   }
   return 0;
}

HeapBase *EmuHeap::findHeap(unsigned int handle) {
   EmuHeap *h = NULL;
   for (h = (EmuHeap*)primaryHeap; h; h = (EmuHeap*)h->nextHeap) {
      if (h->base == handle) return h;
   }
   return NULL;
}

bool checkHeapSize(unsigned int base, unsigned int newaddr, unsigned int max) {
//msg("checkHeapSize: base: %x, newsize: %x, max: %x\n", base, newsize, max);
   if (newaddr > max) {
      return false;
   }
   segment_t *h = getseg(base);
   if (newaddr > h->endEA) {
      //need to grow our heap segment
      unsigned int newsize = ((newaddr - base) + 0xFFF) & ~0xFFF;
      set_segm_end(base, base + newsize, 0);
   }
   return true;
}

void readLegacyHeap(int heapNum, Buffer &bIn, Buffer &bOut, unsigned int num_blocks) {
   unsigned int base, max, sz;
   Buffer mb;
   bIn.read((char*)&base, sizeof(base));
   bOut.write(&base, sizeof(base));
   bIn.read((char*)&max, sizeof(max));
   if (heapNum == 0) {
      MemMgr::mmap(base, 0x1000, 0, MM_MAP_FIXED, ".heap");
   }
   else {
      char buf[16];
      ::qsnprintf(buf, 16, ".heap%d", heapNum);
      MemMgr::mmap(base, 0x1000, 0, MM_MAP_FIXED, buf);
   }
   for (unsigned int i = 0; i < num_blocks; i++) {
      unsigned int b, s;
      bIn.read((char*)&b, sizeof(s));
      bOut.write(&b, sizeof(b));
      bIn.read((char*)&s, sizeof(s));
      bOut.write(&s, sizeof(s));
      checkHeapSize(base, b + s, max);
      for (unsigned int j = 0; j < s; j++) {
         int val;
         bIn.read((char*)&val, 1);
         patch_byte(b + j, val);
      }
   }
   segment_t *h = getseg(base);
   sz = (unsigned int)(h->endEA - h->startEA);
   bOut.write((char*)&sz, sizeof(sz));
   bOut.write((char*)&max, sizeof(max));
   bOut.write(mb.get_buf(), mb.get_wlen());
}

void createLegacyHeap(Buffer &b) {
   Buffer hb;
   unsigned int n;
   unsigned int num_heaps = 1;
   b.read((char*)&n, sizeof(n));
   
   //test for multi-heap
   if (n == HEAP_MAGIC) {
      b.read((char*)&num_heaps, sizeof(num_heaps));
   }
   else { //only a single heap, we already have n
      b.rewind(4);
   }
   hb.write((char*)&num_heaps, sizeof(num_heaps));
   for (unsigned int i = 0; i < num_heaps; i++) {
      b.read((char*)&n, sizeof(n));
      hb.write((char*)&n, sizeof(n));
      readLegacyHeap(i, b, hb, n);
   }
   EmuHeap::loadHeapLayout(hb);
}
