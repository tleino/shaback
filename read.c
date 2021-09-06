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

#include "shaback.h"

#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <zlib.h>
#include <fcntl.h>

static int
restore_file(struct shaback *shaback, struct shaback_entry *ep)
{
	int fd;
	char *p;
	static char buf[1024 * 64];
	ssize_t n;
	size_t sz;
	ssize_t remaining;
	struct timespec ts[2] = { 0 };

	umask(0);

	if (lseek(shaback->fd, ep->offset, SEEK_SET) == -1) {
		warn("lseek");
		return -1;
	}

	p = ep->path;
	if (*p == '/')
		p++;

	if (*p == '\0') {
		warnx("empty filename");
		return 0;
	}

	if (*p == '.' && *(p+1) == '\0') {
		warnx("skipped .");
		return 0;
	}

	if (ep->type == 'd') {
		if (mkdir(p, ep->mode) == -1) {
			warn("mkdir %s", ep->path);
			return -1;
		}
	} else if (ep->type == 'l') {
		if (symlink(ep->link_path, p) == -1) {
			warn("symlink %s", p);
			return -1;
		}
	} else if (ep->type == 'f') {
		fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
		    ep->mode);
		remaining = ep->compressed_size;
		if (remaining == 0)
			remaining = ep->size;

		if (ep->compressed_size > 0) {
			int ret;
			unsigned have;
			z_stream strm;
			unsigned char out[1024 * 64];

			if (ep->is_dup)
				printf("%s (uncompress, redup)\n", ep->path);
			else
				printf("%s (uncompress)\n", ep->path);

			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;
			strm.avail_in = 0;
			strm.next_in = Z_NULL;
			ret = inflateInit(&strm);
			if (ret != Z_OK) {
				warnx("failed to uncompress");
				return -1;
			}

			while (remaining > 0) {
				sz = remaining < sizeof(buf) ? remaining :
				    sizeof(buf);
				if (sz != sizeof(buf))
					sz = sz/512*512+512;
				n = read(shaback->fd, buf, sz);
				if (n == -1 || n == 0)
					break;

				strm.avail_in = n;
				strm.next_in = buf;

				do {
					strm.avail_out = 1024 * 64;
					strm.next_out = out;

					ret = inflate(&strm, Z_NO_FLUSH);
					switch (ret) {
					case Z_NEED_DICT:
						ret = Z_DATA_ERROR;
					case Z_DATA_ERROR:
					case Z_MEM_ERROR:
						warnx("inflate error");
						(void)inflateEnd(&strm);
						return -1;
					}

					have = (1024*64) - strm.avail_out;
					write(fd, out, have);
					remaining -= n;
				} while (strm.avail_out == 0);
			}
			(void)inflateEnd(&strm);
		} else {
			if (ep->is_dup)
				printf("%s (redup)\n", ep->path);
			else
				printf("%s\n", ep->path);
			while (remaining > 0) {
				sz = remaining < sizeof(buf) ? remaining :
				    sizeof(buf);
				if (sz != sizeof(buf))
					sz = sz/512*512+512;
				n = read(shaback->fd, buf, sz);
				if (n == -1 || n == 0)
					break;
				write(fd, buf, remaining < n ? remaining : n);
				remaining -= n;
			}
		}
		if (fd == -1) {
			warn("open %s", ep->path);
			return -1;
		}
		close(fd);
	}
	ts[0].tv_sec = ep->atime;
	ts[1].tv_sec = ep->mtime;
	if (utimensat(AT_FDCWD, p, ts, AT_SYMLINK_NOFOLLOW) == -1) {
		warn("futimes %s", p);
		return -1;
	}
	if (geteuid() == 0) {
		if (fchownat(AT_FDCWD, p, ep->uid, ep->gid,
		    AT_SYMLINK_NOFOLLOW) == -1) {
			warn("fchownat %s", p);
			return -1;
		}
	}
	
	return 0;
}

int
shaback_read(struct shaback *shaback, int argc, char **argv)
{
	shaback->target = *argv++;
	argc--;

	shaback->hashmap = calloc(HASHMAP_ALLOC,
	    sizeof(struct shaback_hash_entry *));
	if (shaback->hashmap == NULL)
		err(1, "calloc");

	if ((shaback->fd = open(shaback->target, O_RDONLY, 0)) == -1) {
		warn("%s", shaback->target);
		return -1;
	}

	if (shaback_read_index(shaback, restore_file) == -1) {
		warn("shaback_read_index");
		close(shaback->fd);
		return -1;
	}

	close(shaback->fd);
	return 0;
}
