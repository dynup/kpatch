/* SPDX-License-Identifier: GPL-2.0 */
/*
 * RISC-V instruction encoding helpers for kpatch.
 *
 * Pure instruction field extraction and encoding functions with no
 * dependency on kpatch data structures.
 */

#ifndef _KPATCH_RISCV_INSN_H_
#define _KPATCH_RISCV_INSN_H_

#define RISCV_REG_MASK		0x1f
#define RISCV_OPCODE_MASK	0x7f

#define RISCV_OPCODE_LOAD	0x03
#define RISCV_OPCODE_OP_IMM	0x13

#define RISCV_FUNCT3_LD		0x3

#define RISCV_OPCODE_FUNCT3_MASK ((0x7u << 12) | RISCV_OPCODE_MASK)

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

static inline unsigned int riscv_set_opcode_funct3(unsigned int insn,
						   unsigned int opcode,
						   unsigned int funct3)
{
	return (insn & ~RISCV_OPCODE_FUNCT3_MASK) | (funct3 << 12) | opcode;
}

#endif /* _KPATCH_RISCV_INSN_H_ */
