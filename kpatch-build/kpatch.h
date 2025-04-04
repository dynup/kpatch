#ifndef _KPATCH_H_
#define _KPATCH_H_

enum exit_status {
	EXIT_STATUS_SUCCESS		= 0,
	EXIT_STATUS_ERROR		= 1,
	EXIT_STATUS_DIFF_FATAL		= 2,
	EXIT_STATUS_NO_CHANGE		= 3,
};

#define GET_CHILD_OBJ(obj) \
((obj) == NULL ? NULL : ({ \
	char *_childobj = strchr((obj), '/'); \
	(_childobj == NULL) ? (obj) : (_childobj + 1 ); \
}))

#endif /* _KPATCH_H_ */
