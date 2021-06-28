#ifndef FLOW_H
#define FLOW_H

#include "lib.h"

extern unsigned long bb_generation;

#define REPEAT_CSE		(1 << 0)
#define REPEAT_CFG_CLEANUP	(1 << 2)

struct entrypoint;
struct instruction;

extern int remove_phisources(struct basic_block *par, struct basic_block *old);

extern int simplify_flow(struct entrypoint *ep);

extern void kill_dead_stores(struct entrypoint *ep, pseudo_t addr, int local);
extern void simplify_symbol_usage(struct entrypoint *ep);
extern void simplify_memops(struct entrypoint *ep);
extern void pack_basic_blocks(struct entrypoint *ep);
extern int simplify_cfg_early(struct entrypoint *ep);
extern int convert_to_jump(struct instruction *insn, struct basic_block *target);

extern void convert_instruction_target(struct instruction *insn, pseudo_t src);
extern void remove_dead_insns(struct entrypoint *);

extern void kill_bb(struct basic_block *);
extern void kill_use(pseudo_t *);
extern void remove_use(pseudo_t *);
extern void kill_unreachable_bbs(struct entrypoint *ep);

extern int kill_insn(struct instruction *, int force);
static inline int kill_instruction(struct instruction *insn)
{
	return kill_insn(insn, 0);
}
static inline int kill_instruction_force(struct instruction *insn)
{
	return kill_insn(insn, 1);
}

void check_access(struct instruction *insn);
int dominates(struct instruction *insn, struct instruction *dom, int local);

extern void vrfy_flow(struct entrypoint *ep);
extern int pseudo_in_list(struct pseudo_list *list, pseudo_t pseudo);

#endif
