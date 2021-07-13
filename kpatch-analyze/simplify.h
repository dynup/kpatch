#ifndef SIMPLIFY_H
#define SIMPLIFY_H

#include "linearize.h"

int simplify_instruction(struct instruction *insn);

int replace_with_pseudo(struct instruction *insn, pseudo_t pseudo);

#endif
