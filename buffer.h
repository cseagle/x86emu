/*
   Source for x86 emulator IdaPro plugin
   File: buffer.h
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

#ifndef __BUFFER_H
#define __BUFFER_H

#include <stddef.h>

#define BUFFER_MAGIC 0x861DA000
#define BUFFER_MAGIC_MASK 0xFFFFF000
#define VERSION(n) (BUFFER_MAGIC | n)

class Buffer {
public:
   Buffer();
   Buffer(unsigned int magic);
   Buffer(unsigned char *buf, size_t len);
   ~Buffer();
   
   int read(void *data, size_t len);
   bool rewind(size_t amt);
   int write(const void *data, size_t len);
   int readString(char **str);
   int writeString(const char *str);
   
   unsigned char *get_buf();
   size_t get_wlen();
   size_t get_rlen();
   bool has_error() {return error;};
   void reset_error() {error = false;};
   unsigned int getMagic() {return magic;};
   unsigned int getVersion();

private:
   Buffer(const Buffer & /*b*/) {};
   int check_size(size_t max);
   void init(size_t size);
   
   unsigned int magic;
   unsigned char *bptr;
   size_t rptr;
   size_t wptr;
   size_t sz;
   bool error;
};

#endif

