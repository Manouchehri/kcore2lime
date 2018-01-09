#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri

'''
typedef struct {
	unsigned int magic;
	unsigned int version;
	unsigned long long s_addr;
	unsigned long long e_addr;
	unsigned char reserved[8];
} __attribute__ ((__packed__)) lime_range;

l.magic   = 0x4C694D45;
l.version = 1; 
l.s_addr  = phys_off;
l.e_addr  = phys_off + size - 1;
printf("l.s_addr: %llx l.e_addr: %llx\n", l.s_addr, l.e_addr);
memset(&l.reserved, 0x00, sizeof(l.reserved));

phdr_addr: 158 phys_start: 1000 p_vaddr: ffff880000001000 p_memsz: 8e000 p_paddr: 0 p_offset: 80000003000 p_type: 1 p_filesz: 8e000 p_flags: 7 p_align: 1000
_write_lime_header: Made lime header for start: 1000 end: 8efff
Wrote 581632 bytes from 1000

00000000: 454d 694c 0100 0000 0010 0000 0000 0000  EMiL............
00000010: ffef 0800 0000 0000 0000 0000 0000 0000  ................
'''



import struct
import sys
# sys.path.append('~/patchkit/util')
from util import elffile

lime_magic = 0x4C694D45
lime_version = 1
# phys_off = 0x1000
# size = 0x8e000
# header = struct.pack('IIQQ8s', magic, version, phys_off, phys_off+size-1, '')
# binascii.b2a_hex(header)

binary = elffile.open('./kcore')

processed_offsets = []

with open("/samples/test.lime", "wb") as output_file:
	for ph in binary.progs:
		offset = ph.offset
		size = ph.filesz
		if ph.type == elffile.PT['PT_LOAD'] and offset not in processed_offsets:
			processed_offsets.append(offset)
			start = offset # Not sure if this is correct
			header = struct.pack('IIQQ8s', lime_magic, lime_version, offset, offset + size - 1, '')
			output_file.write(header)
			output_file.write(ph.data)
	output_file.close()

'''
<ElfProgramHeader32l@0x7fc84d3a29d0: type=PT_NOTE, offset=180, vaddr=0x0, paddr=0x0, filesz=3660, memsz=0, flags=0x0, align=0>
<ElfProgramHeader32l@0x7fc84d3a2510: type=PT_LOAD, offset=943714304, vaddr=0xf83fe000, paddr=0x0, filesz=125829120, memsz=125829120, flags=0x7, align=4096>
<ElfProgramHeader32l@0x7fc84d3a2550: type=PT_LOAD, offset=943714304, vaddr=0xf83fe000, paddr=0x0, filesz=125829120, memsz=125829120, flags=0x7, align=4096>
<ElfProgramHeader32l@0x7fc84d3a2590: type=PT_LOAD, offset=4096, vaddr=0xc0000000, paddr=0x0, filesz=935321600, memsz=935321600, flags=0x7, align=4096>
'''
