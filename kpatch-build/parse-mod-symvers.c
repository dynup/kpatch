#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

/*
 * parse-mod-symvers.c
 *
 * These parsing and file-related functions were largely pilfered
 * from scripts/mod/modpost.c, with a few modifications.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

static void *grab_file(const char *filename, unsigned long *size) {
	struct stat st;
	void *map = MAP_FAILED;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st))
		goto failed;

	*size = st.st_size;
	map = mmap(NULL, *size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);

failed:
	close(fd);
	if (map == MAP_FAILED)
		return NULL;
	return map;
}

/**
  * Return a copy of the next line in a mmap'ed file.
  * spaces in the beginning of the line is trimmed away.
  * Return a pointer to a static buffer.
  **/
static char *get_next_line(unsigned long *pos, void *file, unsigned long size)
{
	static char line[4096];
	int skip = 1;
	size_t len = 0;
	signed char *p = (signed char *)file + *pos;
	char *s = line;

	for (; *pos < size ; (*pos)++) {
		if (skip && isspace(*p)) {
			p++;
			continue;
		}
		skip = 0;
		if (*p != '\n' && (*pos < size)) {
			len++;
			*s++ = *p++;
			if (len > 4095)
				break; /* Too long, stop */
		} else {
			/* End of string */
			*s = '\0';
			return line;
		}
	}
	/* End of buffer */
	return NULL;
}

static void release_file(void *file, unsigned long size)
{
	munmap(file, size);
}

/*
 * find_exported_symbol_objname - find the object/module an exported
 * symbol belongs to.
 *
 * Module.symvers line format:
 * 0x12345678<tab>symbol<tab>module[[<tab>export]<tab>something]
 */
char *find_exported_symbol_objname(const char *fname, char *symname)
{
	char *s, *m, *modname, *export, *end;
	unsigned long size, pos = 0;
	void *file = grab_file(fname, &size);
	char *line;

	if (!file)
		goto fail;

	while ((line = get_next_line(&pos, file, size))) {
		if (!(s = strchr(line, '\t')))
			goto fail;
		*s++ = '\0';
		if (!(m = strchr(s, '\t')))
			goto fail;
		*m++ = '\0';
		if ((export = strchr(m, '\t')) != NULL)
			*export++ = '\0';
		if (export && ((end = strchr(export, '\t')) != NULL))
			*end = '\0';
		if (*s == '\0' || *m == '\0')
			goto fail;
		if (!strcmp(symname, s)) {
			modname = strdup(m);
			release_file(file, size);
			return modname;
		}
	}
fail:
	release_file(file, size);
	return NULL;
}
