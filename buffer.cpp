/*
   Source for x86 emulator IdaPro plugin
   File: buffer.cpp
   Copyright (c) 2005-2022 Chris Eagle
   
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
#include "buffer.h"

#define BLOCK_SIZE 0x100   //keep this a power of two

Buffer::Buffer() {
   init(BLOCK_SIZE);
}

Buffer::Buffer(unsigned int magic) {
   init(BLOCK_SIZE);
   this->magic = magic;
   write(&magic, sizeof(magic));
}

Buffer::Buffer(unsigned char *buf, size_t len) {
   init(len);
   if (!error) {
      if (len >= 4) {  //check for presence of BUFFER_MAGIC
         unsigned int m = *(unsigned int*)buf;
         if ((m & BUFFER_MAGIC_MASK) == BUFFER_MAGIC) {
            magic = m;
            len -= 4;  //adjust length
            buf += 4;  //adjust buffer start
         }
      }
      memcpy(bptr, buf, len);
   }
   wptr = sz;
}

void Buffer::init(size_t size) {
   bptr = (unsigned char *)malloc(size);
   sz = bptr ? size : 0;
   rptr = wptr = 0;
   error = sz != size;
   magic = 0;
}

Buffer::~Buffer() {
   free(bptr);
}

int Buffer::read(void *data, size_t len) {
   if ((rptr + len) <= sz) {
      memcpy(data, bptr + rptr, len);
      rptr += len;
      return 0;
   }
   error = true;
   return 1;
}

bool Buffer::rewind(size_t amt) {
   if (rptr >= amt) {
      rptr -= amt;
      return true;
   }
   return false;
}

int Buffer::write(const void *data, size_t len) {
   if (!check_size(wptr + len)) {
      memcpy(bptr + wptr, data, len);
      wptr += len;
      return 0;
	}
   error = true;
   return 1;
}

int Buffer::readString(char **str) {
   size_t len;
   if (read(&len, sizeof(len)) == 0) {
      *str = (char*)malloc(len);
      if (*str && read(*str, len) == 0) return 0;
      free(*str);
   }
   error = true;
   return 1;
}

int Buffer::writeString(const char *str) {
   size_t len = strlen(str) + 1;
   if (write(&len, sizeof(len)) == 0) {
      return write(str, len);
   }
   error = true;
   return 1;
}

unsigned char *Buffer::get_buf() {
   return bptr;
}

size_t Buffer::get_wlen() {
   return wptr;
}

size_t Buffer::get_rlen() {
   return rptr;
}

int Buffer::check_size(size_t max) {
	if (max <= sz) return 0;
	max = (max + BLOCK_SIZE) & ~(BLOCK_SIZE - 1);   //round up to next BLOCK_SIZE
	unsigned char *tmp = (unsigned char *)realloc(bptr, max);
	if (tmp) {
	   bptr = tmp;
   	sz = max;
   	return 0;
	}
   error = true;
	return 1;
}

unsigned int Buffer::getVersion() {
   return ((magic & BUFFER_MAGIC_MASK) == BUFFER_MAGIC) ? (magic & ~BUFFER_MAGIC_MASK) : 0;
}

