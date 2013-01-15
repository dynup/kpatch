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

	/* restore regs owned by original calling function */
	popq %rax
	movq RBP(%rax), %rbp
	movq RBX(%rax), %rbx
	movq R12(%rax), %r12
	movq R13(%rax), %r13
	movq R14(%rax), %r14
	movq R15(%rax), %r15

	/* restore arg registers and stack for new function */
	movq RDI(%rax), %rdi
	movq RSI(%rax), %rsi
	movq RDX(%rax), %rdx
	movq RCX(%rax), %rcx
	movq RSP(%rax), %rsp

	/* jump to new function */
	jmpq *%r10

bail:
	ret
