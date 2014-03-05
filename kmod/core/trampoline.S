/*
 * kpatch trampoline
 *
 * Copyright (C) 2013 Josh Poimboeuf <jpoimboe@redhat.com>
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

#include <linux/linkage.h>
#include <asm/calling.h>

GLOBAL(kpatch_trampoline)

	pushq %rcx
	pushq %rdi

	callq kpatch_ftrace_hacks

	leaq kpatch_funcs, %r10

	/*
	 * TODO: if preemption is possible then we'll need to think about how
	 * to ensure atomic access to the array and how to ensure activeness
	 * safety here.  if preemption is enabled then we need to make sure the
	 * IP isn't inside kpatch_trampoline for any task.
	 */

	 /* TODO: save/restore flags? */

	/* find new function in func_list */
	popq %rdi
loop:
	movq (%r10), %r9
	cmpq %r9, %rdi
	je found

	/*
	 * Check for the rare case where we don't have a new function to call.
	 * This can happen in the small window of time during patch module
	 * insmod after it has called register_ftrace_function() but before it
	 * has called stop_machine() to do the activeness safety check and the
	 * array update.  In this case we just return and let the old function
	 * run.
	 */
	cmpq $0, %r9
	je bail

	addq $40, %r10 /* FIXME http://docs.blackfin.uclinux.org/doku.php?id=toolchain:gas:structs */
	jmp loop

found:
	/* get new function address */
	movq 8(%r10), %r10

	/* tell ftrace to return to new function */
	popq %rax
	movq %r10, RIP(%rax)

bail:
	retq
