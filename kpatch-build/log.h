#ifndef _LOG_H_
#define _LOG_H_

/* Files that include log.h must define loglevel and childobj */
extern enum loglevel loglevel;
extern char *childobj;

#define ERROR(format, ...) \
	error(1, 0, "ERROR: %s: %s: %d: " format, childobj, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define log_debug(format, ...) log(DEBUG, format, ##__VA_ARGS__)
#define log_normal(format, ...) log(NORMAL, "%s: " format, childobj, ##__VA_ARGS__)

#define log(level, format, ...) \
({ \
	if (loglevel <= (level)) \
		printf(format, ##__VA_ARGS__); \
})

enum loglevel {
	DEBUG,
	NORMAL
};
#endif /* _LOG_H_ */
