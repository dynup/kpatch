// SPDX-License-Identifier: MIT
//
// SSA conversion
// Copyright (C) 2005 Luc Van Oostenryck
//

#include <assert.h>
#include "ssa.h"
#include "lib.h"
#include "dominate.h"
#include "flowgraph.h"
#include "linearize.h"
#include "simplify.h"
#include "flow.h"


// Is it possible and desirable for this to be promoted to a pseudo?
static inline bool is_promotable(struct symbol *type)
{
	struct symbol *member;
	int bf_seen;
	int nbr;

	if (type->type == SYM_NODE)
		type = type->ctype.base_type;
	switch (type->type) {
	case SYM_ENUM:
	case SYM_BITFIELD:
	case SYM_PTR:
	case SYM_RESTRICT:	// OK, always integer types
		return 1;
	case SYM_STRUCT:
		// we allow a single scalar field
		// but a run of bitfields count for 1
		// (and packed bifields are excluded).
		if (type->packed)
			return 0;
		nbr = 0;
		bf_seen = 0;
		FOR_EACH_PTR(type->symbol_list, member) {
			if (is_bitfield_type(member)) {
				if (bf_seen)
					continue;
				bf_seen = 1;
			} else {
				bf_seen = 0;
			}
			if (!is_scalar_type(member))
				return 0;
			if (nbr++)
				return 0;
		} END_FOR_EACH_PTR(member);
		if (bf_seen && (type->bit_size > long_ctype.bit_size))
			return 0;
		return 1;
	case SYM_UNION:
		// FIXME: should be like struct but has problem
		//        when used with/for type cohercion
		// -----> OK if only same sized integral types
		FOR_EACH_PTR(type->symbol_list, member) {
			if (member->bit_size != type->bit_size)
				return 0;
			if (!is_integral_type(member))
				return 0;
		} END_FOR_EACH_PTR(member);
		return 1;
	default:
		break;
	}
	if (type->ctype.base_type == &int_type)
		return 1;
	if (type->ctype.base_type == &fp_type)
		return 1;
	return 0;
}

static void kill_store(struct instruction *insn)
{
	remove_use(&insn->src);
	remove_use(&insn->target);
	insn->bb = NULL;
}

static bool same_memop(struct instruction *a, struct instruction *b)
{
	if (a->size != b->size || a->offset != b->offset)
		return false;
	if (is_integral_type(a->type) && is_float_type(b->type))
		return false;
	if (is_float_type(a->type) && is_integral_type(b->type))
		return false;
	return true;
}

static void rewrite_local_var(struct basic_block *bb, pseudo_t addr, int nbr_stores, int nbr_uses)
{
	struct instruction *store = NULL;
	struct instruction *insn;
	bool remove = false;

	if (!bb)
		return;

	FOR_EACH_PTR(bb->insns, insn) {

		if (!insn->bb || insn->src != addr)
			continue;
		switch (insn->opcode) {
		case OP_LOAD:
			if (!store)
				replace_with_pseudo(insn, undef_pseudo());
			else if (same_memop(store, insn))
				replace_with_pseudo(insn, store->target);
			else
				remove = false;
			break;
		case OP_STORE:
			store = insn;
			remove = true;
			break;
		}
	} END_FOR_EACH_PTR(insn);
	if (remove)
		kill_store(store);
}

// we would like to know:
// is there one or more stores?
// are all loads & stores local/done in a single block?
static void ssa_convert_one_var(struct entrypoint *ep, struct symbol *var)
{
	unsigned long generation = ++bb_generation;
	struct basic_block_list *alpha = NULL;
	struct basic_block_list *idf = NULL;
	struct basic_block *samebb = NULL;
	struct basic_block *bb;
	struct pseudo_user *pu;
	unsigned long mod = var->ctype.modifiers;
	bool local = true;
	int nbr_stores = 0;
	int nbr_uses   = 0;
	pseudo_t addr;

	/* Never used as a symbol? */
	addr = var->pseudo;
	if (!addr)
		return;

	/* We don't do coverage analysis of volatiles.. */
	if (mod & MOD_VOLATILE)
		return;

	/* ..and symbols with external visibility need more care */
	mod &= (MOD_NONLOCAL | MOD_STATIC | MOD_ADDRESSABLE);
	if (mod)
		goto external_visibility;

	if (!is_promotable(var))
		return;

	// 1) insert in the worklist all BBs that may modify var
	FOR_EACH_PTR(addr->users, pu) {
		struct instruction *insn = pu->insn;
		struct basic_block *bb = insn->bb;

		switch (insn->opcode) {
		case OP_STORE:
			nbr_stores++;
			if (bb->generation != generation) {
				bb->generation = generation;
				add_bb(&alpha, bb);
			}
			/* fall through */
		case OP_LOAD:
			if (local) {
				if (!samebb)
					samebb = bb;
				else if (samebb != bb)
					local = false;
			}
			nbr_uses++;
			break;
		case OP_SYMADDR:
			mod |= MOD_ADDRESSABLE;
			goto external_visibility;
		default:
			warning(var->pos, "symbol '%s' pseudo used in unexpected way",
				show_ident(var->ident));
		}
	} END_FOR_EACH_PTR(pu);

	// if all uses are local to a single block
	// they can easily be rewritten and doesn't need phi-nodes
	// FIXME: could be done for extended BB too
	if (local) {
		rewrite_local_var(samebb, addr, nbr_stores, nbr_uses);
		return;
	}

	idf_compute(ep, &idf, alpha);
	FOR_EACH_PTR(idf, bb) {
		struct instruction *node = insert_phi_node(bb, var);
		node->phi_var = var->pseudo;
	} END_FOR_EACH_PTR(bb);
	var->torename = 1;

external_visibility:
	if (mod & (MOD_NONLOCAL | MOD_STATIC))
		return;
	kill_dead_stores(ep, addr, !mod);
}

static struct instruction *lookup_var(struct basic_block *bb, struct symbol *var)
{
	do {
		struct instruction *insn = phi_map_lookup(bb->phi_map, var);
		if (insn)
			return insn;
	} while ((bb = bb->idom));
	return NULL;
}

static struct instruction_list *phis_all;
static struct instruction_list *phis_used;
static struct instruction_list *stores;

static bool matching_load(struct instruction *def, struct instruction *insn)
{
	if (insn->size != def->size)
		return false;
	switch (def->opcode) {
	case OP_STORE:
	case OP_LOAD:
		if (insn->offset != def->offset)
			return false;
	case OP_PHI:
		break;
	default:
		return false;
	}
	return true;
}

static void ssa_rename_insn(struct basic_block *bb, struct instruction *insn)
{
	struct instruction *def;
	struct symbol *var;
	pseudo_t addr;
	pseudo_t val;

	switch (insn->opcode) {
	case OP_STORE:
		addr = insn->src;
		if (addr->type != PSEUDO_SYM)
			break;
		var = addr->sym;
		if (!var || !var->torename)
			break;
		phi_map_update(&bb->phi_map, var, insn);
		add_instruction(&stores, insn);
		break;
	case OP_LOAD:
		addr = insn->src;
		if (addr->type != PSEUDO_SYM)
			break;
		var = addr->sym;
		if (!var || !var->torename)
			break;
		def = lookup_var(bb, var);
		if (!def) {
			val = undef_pseudo();
		} else if (!matching_load(def, insn)) {
			var->torename = false;
			break;
		} else {
			val = def->target;
		}
		replace_with_pseudo(insn, val);
		break;
	case OP_PHI:
		var = insn->type;
		if (!var || !var->torename)
			break;
		phi_map_update(&bb->phi_map, var, insn);
		add_instruction(&phis_all, insn);
		break;
	}
}

static void ssa_rename_insns(struct entrypoint *ep)
{
	struct basic_block *bb;

	FOR_EACH_PTR(ep->bbs, bb) {
		struct instruction *insn;
		FOR_EACH_PTR(bb->insns, insn) {
			if (!insn->bb)
				continue;
			ssa_rename_insn(bb, insn);
		} END_FOR_EACH_PTR(insn);
	} END_FOR_EACH_PTR(bb);
}

static void mark_phi_used(pseudo_t val)
{
	struct instruction *node;

	if (val->type != PSEUDO_REG)
		return;
	node = val->def;
	if (node->opcode != OP_PHI)
		return;
	if (node->used)
		return;
	node->used = 1;
	add_instruction(&phis_used, node);
}

static void ssa_rename_phi(struct instruction *insn)
{
	struct basic_block *par;
	struct symbol *var;

	if (!insn->phi_var)
		return;
	var = insn->phi_var->sym;
	if (!var->torename)
		return;
	FOR_EACH_PTR(insn->bb->parents, par) {
		struct instruction *def = lookup_var(par, var);
		pseudo_t val = def ? def->target : undef_pseudo();
		struct instruction *phisrc = alloc_phisrc(val, var);
		pseudo_t phi = phisrc->target;
		phi->ident = var->ident;
		insert_last_instruction(par, phisrc);
		link_phi(insn, phi);
		mark_phi_used(val);
	} END_FOR_EACH_PTR(par);
}

static void ssa_rename_phis(struct entrypoint *ep)
{
	struct instruction *phi;

	phis_used = NULL;
	FOR_EACH_PTR(phis_all, phi) {
		if (has_users(phi->target)) {
			phi->used = 1;
			add_instruction(&phis_used, phi);
		}
	} END_FOR_EACH_PTR(phi);

	FOR_EACH_PTR(phis_used, phi) {
		if (!phi->bb)
			continue;
		ssa_rename_phi(phi);
	} END_FOR_EACH_PTR(phi);
}

static void remove_dead_stores(struct instruction_list *stores)
{
	struct instruction *store;

	FOR_EACH_PTR(stores, store) {
		struct symbol *var = store->addr->sym;

		if (var->torename)
			kill_store(store);
	} END_FOR_EACH_PTR(store);
}

void ssa_convert(struct entrypoint *ep)
{
	struct basic_block *bb;
	pseudo_t pseudo;
	int first, last;

	// calculate the number of BBs
	first = ep->entry->bb->nr;
	last = first;
	FOR_EACH_PTR(ep->bbs, bb) {
		int nr = bb->nr;
		if (nr > last)
			last = nr;
		bb->phi_map = NULL;
	} END_FOR_EACH_PTR(bb);

	// try to promote memory accesses to pseudos
	stores = NULL;
	FOR_EACH_PTR(ep->accesses, pseudo) {
		ssa_convert_one_var(ep, pseudo->sym);
	} END_FOR_EACH_PTR(pseudo);

	// rename the converted accesses
	phis_all = phis_used = NULL;
	ssa_rename_insns(ep);
	ssa_rename_phis(ep);

	// remove now dead stores
	remove_dead_stores(stores);
}
