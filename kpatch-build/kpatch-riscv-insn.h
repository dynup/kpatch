/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RISC-V instruction encoding helpers for kpatch.
 *
 * Pure instruction field extraction and encoding functions with no
 * dependency on kpatch data structures.
 */

#ifndef _KPATCH_RISCV_INSN_H_
#define _KPATCH_RISCV_INSN_H_

#include <stdint.h>
#include "log.h"

/* Instruction and field sizes */
#define RISCV_INSN_SIZE		4
#define RISCV_REG_MASK		0x1f
#define RISCV_OPCODE_MASK	0x7f

/* Opcodes */
#define RISCV_OPCODE_LOAD	0x03
#define RISCV_OPCODE_OP_IMM	0x13
#define RISCV_OPCODE_AUIPC	0x17
#define RISCV_OPCODE_JALR	0x67
#define RISCV_OPCODE_JAL	0x6f

/* Funct3 */
#define RISCV_FUNCT3_LD		0x3

/* Composite masks */
#define RISCV_OPCODE_FUNCT3_MASK ((0x7u << 12) | RISCV_OPCODE_MASK)
#define RISCV_IMM_MASK		0xfff00000u	/* I-type immediate, bits [31:20] */

/* Trampoline anchor index base */
#define RISCV_TRAMPOLINE_INDEX_BASE 0x80000000u

/* Register names */
#define RISCV_REG_ZERO		0

/* Field extraction */
static inline unsigned int riscv_opcode(unsigned int insn)
{
	return insn & RISCV_OPCODE_MASK;
}

static inline unsigned int riscv_rd(unsigned int insn)
{
	return (insn >> 7) & RISCV_REG_MASK;
}

static inline unsigned int riscv_rs1(unsigned int insn)
{
	return (insn >> 15) & RISCV_REG_MASK;
}

/* Field modification */
static inline unsigned int riscv_set_opcode_funct3(unsigned int insn,
						   unsigned int opcode,
						   unsigned int funct3)
{
	return (insn & ~RISCV_OPCODE_FUNCT3_MASK) | (funct3 << 12) | opcode;
}

/* Common instruction synthesis */
static inline unsigned int riscv_ld_insn(unsigned int rd, unsigned int rs1)
{
	return (rs1 << 15) | (rd << 7) |
	       (RISCV_FUNCT3_LD << 12) | RISCV_OPCODE_LOAD;
}

static inline unsigned int riscv_auipc_insn(unsigned int rd)
{
	return (rd << 7) | RISCV_OPCODE_AUIPC;
}

/* Instruction encoding */
static inline unsigned int encode_riscv_jal(unsigned int rd, long offset)
{
	unsigned long imm;

	if ((offset & 1) || offset < -(1L << 20) || offset >= (1L << 20))
		ERROR("RISC-V JAL target out of range");

	imm = (unsigned long)offset;
	return (unsigned int)(((imm & 0x100000) << 11) |
			      ((imm & 0x7fe) << 20) |
			      ((imm & 0x800) << 9) |
			      (imm & 0xff000)) |
	       (rd << 7) | RISCV_OPCODE_JAL;
}

static inline void encode_riscv_auipc_jalr(unsigned int rd, long offset,
					   unsigned int *auipc,
					   unsigned int *jalr)
{
	long hi20, lo12;

	if (offset < -(1L << 31) || offset >= (1L << 31))
		ERROR("RISC-V AUIPC/JALR target out of range");

	hi20 = (offset + 0x800) & ~0xfffL;
	lo12 = offset - hi20;
	*auipc = ((unsigned int)hi20 & 0xfffff000u) |
		 (rd << 7) | RISCV_OPCODE_AUIPC;
	*jalr = (((unsigned int)lo12 & 0xfffu) << 20) |
		(rd << 15) | RISCV_OPCODE_JALR;
}

#endif /* _KPATCH_RISCV_INSN_H_ */
