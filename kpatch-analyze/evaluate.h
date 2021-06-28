#ifndef EVALUATE_H
#define EVALUATE_H

struct expression;
struct expression_list;
struct statement;
struct symbol;
struct symbol_list;

///
// evaluate the type of an expression
// @expr: the expression to be evaluated
// @return: the type of the expression or ``NULL``
//	if the expression can't be evaluated
struct symbol *evaluate_expression(struct expression *expr);

///
// evaluate the type of a statement
// @stmt: the statement to be evaluated
// @return: the type of the statement or ``NULL``
//	if it can't be evaluated
struct symbol *evaluate_statement(struct statement *stmt);

///
// evaluate the type of a set of symbols
// @list: the list of the symbol to be evaluated
void evaluate_symbol_list(struct symbol_list *list);

///
// evaluate the arguments of a function
// @argtypes: the list of the types in the prototype
// @args: the list of the effective arguments
int evaluate_arguments(struct symbol_list *argtypes, struct expression_list *args);

#endif
