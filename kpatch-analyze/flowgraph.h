#ifndef FLOWGRAPH_H
#define FLOWGRAPH_H

///
// Utilities for flowgraphs
// ------------------------

#include <stdbool.h>

struct entrypoint;
struct basic_block;

///
// Set the BB's reverse postorder links
// Each BB will also have its 'order number' set.
int cfg_postorder(struct entrypoint *ep);

///
// Build the dominance tree.
// Each BB will then have:
//	- a link to its immediate dominator (::idom)
//	- the list of BB it immediately dominates (::doms)
//	- its level in the dominance tree (::dom_level)
void domtree_build(struct entrypoint *ep);

///
// Test the dominance between two basic blocks.
// @a: the basic block expected to dominate
// @b: the basic block expected to be dominated
// @return: ``true`` if @a dominates @b, ``false`` otherwise.
bool domtree_dominates(struct basic_block *a, struct basic_block *b);

#endif
