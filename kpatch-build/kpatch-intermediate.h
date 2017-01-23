/*
 * kpatch-intermediate.h
 *
 * Structures for intermediate .kpatch.* sections
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#ifndef _KPATCH_INTERMEDIATE_H_
#define _KPATCH_INTERMEDIATE_H_

struct kpatch_symbol {
	unsigned long src;
	unsigned long pos;
	unsigned char bind, type;
	char *name;
	char *objname; /* object to which this sym belongs */
};

/* For .kpatch.{symbols,relocations,arch} sections */
struct kpatch_relocation {
	unsigned long dest;
	unsigned int type;
	int addend;
	int offset;
	int external;
	char *objname; /* object to which this rela applies to */
	struct kpatch_symbol *ksym;
};
#endif /* _KPATCH_ELF_H_ */
