/*
 * Copyright (c) 2021, Tommi Leino <namhas@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Here we walk directory tree by using *at() functions for tracking
 * cwd using fds calling the given callback for all files.
 *
 * Directories are dumped before files contained therein so that
 * reconstruction is easier.
 *
 * The original path which begins the dirwalk might be a symlink and
 * it is followed, but other symlinks are not followed but they are
 * dumped as they are.
 */

#include "shaback.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <err.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int			 shaback_dirwalk_fd(struct shaback *,
				    int, DumpCallback);
static int			 shaback_add_path(struct shaback *,
				    const char *);
static void			 shaback_remove_path(struct shaback *);

int
shaback_dirwalk(struct shaback *shaback, int cwd_fd, const char *file,
    DumpCallback dump)
{
	struct stat		 sb;
	int			 fd, ret = 0;

	if (fstatat(cwd_fd, file, &sb, AT_SYMLINK_NOFOLLOW) != 0)
		return -1;

	fd = -1;
	if (S_ISDIR(sb.st_mode) || (S_ISREG(sb.st_mode) && sb.st_size > 0)) {
		fd = openat(cwd_fd, file, O_RDONLY);
		if (fd == -1)
			return -1;
	}

	if (shaback_add_path(shaback, file) == -1)
		return -1;

	if (dump(shaback, fd, shaback->path, &sb) == -1)
		if (errno != 0)
			warn("%s", shaback->path);

	if (S_ISDIR(sb.st_mode)) {
		ret = shaback_dirwalk_fd(shaback, fd, dump);
		fd = -1;	/* closedir closes fd also */
	}

	shaback_remove_path(shaback);
	if (fd != -1)
		if (close(fd) == -1)
			return -1;

	return ret;
}

static int
shaback_add_path(struct shaback *shaback, const char *file)
{
	char *p;
	size_t len, file_len;

	file_len = strlen(file);
	len = shaback->path_len + file_len + 1 + 1;
	if (len >= shaback->path_alloc) {
		if (shaback->path_alloc == 0)
			shaback->path_alloc = 1024;
		else
			shaback->path_alloc *= 2;
		shaback->path = realloc(shaback->path,
		    sizeof(char) * shaback->path_alloc);
		if (shaback->path == NULL)
			return -1;
	}

	p = &shaback->path[shaback->path_len];
	if (shaback->path_len != 0) {
		*p++ = '/';
		shaback->path_len++;
	}
	strcpy(p, file);
	shaback->path_len += file_len;
	return 0;
}

static void
shaback_remove_path(struct shaback *shaback)
{
	while (shaback->path_len--) {
		if (shaback->path[shaback->path_len] == '/') {
			shaback->path[shaback->path_len] = '\0';
			break;
		}
	}
}

static int
shaback_dirwalk_fd(struct shaback *shaback, int fd, DumpCallback dump)
{
	DIR			*dir;
	struct dirent		*ent;

	dir = fdopendir(fd);
	if (dir == NULL) {
		warnx("fdopendir");
		return -1;
	}

	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_name[0] == '.' &&
		    (ent->d_name[1] == '\0' ||
		    (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
			continue;

		if (shaback_dirwalk(shaback, fd, ent->d_name,
		    dump) == -1)
			warn("%s/%s", shaback->path, ent->d_name);
	}
	closedir(dir);

	return 0;
}
