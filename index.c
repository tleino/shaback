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

static ssize_t				 read_str_delim(char *, size_t,
					    int, char **, size_t *);

void
shaback_add_index_entry(struct shaback *shaback, struct shaback_entry *ep)
{
	int			 len = 0;
	uint64_t		 paths_len;
	size_t			 path_len, link_len, remaining;
	char			 *p, *begin;

	begin = p = &shaback->index.buf[shaback->index.len];
	remaining = INDEX_SIZE - shaback->index.len;

	path_len = strlen((const char *) ep->path);
	if (ep->link_path != NULL)
		link_len = strlen((const char *) ep->link_path);

	/*
	 * Calculate the length of file path and link path which
	 * are stored in format of 'file\0link\0\n' and in case link
	 * is missing we have 'file\0\n' i.e. in addition to the
	 * string length, we need to count 2-3 chars extra.
	 */
	paths_len = path_len + 1;
	if (ep->link_path != NULL)
		paths_len += link_len + 1;
	paths_len++;	/* count '\n' */

	if (paths_len >= remaining)
		goto full;

	remaining -= paths_len;

	/*
	 * Add the path names.
	 */
	memcpy(p, ep->path, path_len + 1);
	p += path_len + 1;
	if (ep->link_path != NULL) {
		memcpy(p, ep->link_path, link_len + 1);
		p += link_len + 1;
	}
	*p++ = '\n';
	*p = '\0';

	/*
	 * Add the metadata.
	 */
	len = snprintf(p, remaining,
	    "%llu %c %llu %llu %llu %llu %llu %llu %llu %llu %llu %d %s ",
	    ep->offset, ep->type, ep->inode, ep->ctime,
	    ep->atime, ep->mtime, ep->mode, ep->uid, ep->gid, ep->size,
	    ep->compressed_size, ep->is_dup, ep->hash_file);

	shaback->index.bytes += ep->size;
	shaback->total_bytes += ep->size;

	if (len >= remaining)
		goto full;

	remaining -= len;
	p += len;

	if (SHA1_DIGEST_STRING_LENGTH + 2 >= remaining)
		goto full;

	len = (INDEX_SIZE - shaback->index.len) - remaining;
	SHA1Data((u_int8_t *) begin, len, p);
	p += (SHA1_DIGEST_STRING_LENGTH - 1);
	*p++ = '\n';
	remaining -= (SHA1_DIGEST_STRING_LENGTH - 1 + 1);

	len = (INDEX_SIZE - shaback->index.len) - remaining;
	shaback->index.len += len;
	shaback->index.entries++;
	return;
full:
	memset(begin, '\0', INDEX_SIZE - shaback->index.len);
	shaback_flush_index(shaback);
	shaback_add_index_entry(shaback, ep);
	return;
}

void
shaback_flush_index(struct shaback *shaback)
{
	static time_t t;
	time_t now, diff;

	snprintf(shaback->index.buf, 512,
	    "SHABACK INDEX %llu %llu %d\n", shaback->index.entries,
	    shaback->pos, INDEX_SIZE);

	if (t == 0)
		t = time(0);

	now = time(0);
	diff = now - t;
	if (diff == 0)
		diff = 1;

	printf("Dump index had %llu entries "
	    "(%d MB, %d blocks, %zu MB, %llu MB total, %llu MB/s)\n",
	    shaback->index.entries, INDEX_SIZE / 1024 / 1024, INDEX_SIZE / 512,
	    shaback->index.bytes / 1024 / 1024,
	    shaback->total_bytes / 1024 / 1024,
	    shaback->index.bytes / 1024 / 1024 / diff);

	t = time(0);

	if (lseek(shaback->fd, shaback->index.offset, SEEK_SET) == -1)
		err(1, "lseek");

	if (write(shaback->fd, shaback->index.buf, INDEX_SIZE) != INDEX_SIZE)
		err(1, "write");

	shaback->index.offset = shaback->pos;
	shaback->index.len = 512;
	shaback->index.entries = 0;
	shaback->index.bytes = 0;
	shaback->pos += INDEX_SIZE;
	if (lseek(shaback->fd, shaback->pos, SEEK_SET) == -1)
		err(1, "lseek");
}

static ssize_t
read_str_delim(char *buf, size_t sz, int delim, char **out, size_t *out_alloc)
{
	size_t			 i;

	for (i = 0; i < sz; i++) {
		if (*out_alloc <= (i+1)) {
			if (*out_alloc == 0)
				*out_alloc = 128;
			else
				*out_alloc *= 2;
			*out = realloc(*out, *out_alloc);
			if (*out == NULL)
				return -1;
		}
		(*out)[i] = buf[i];
		if (buf[i] == (unsigned char) delim) {
			(*out)[i+1] = '\0';
			break;
		}
	}
	if (i == sz)
		return -1;
	return ++i;
}

int
shaback_read_index(struct shaback *shaback, IndexCallback cb)
{
	static char buf[INDEX_SIZE], *end, *p;
	ssize_t n;
	off_t next_offset;
	struct shaback_entry e = {0};
	size_t alloc;
	char *s;

	end = &buf[INDEX_SIZE-1];

	n = read(shaback->fd, buf, sizeof(buf));
	if (n != INDEX_SIZE) {
		warnx("failed reading index");
		return -1;
	}

	if (sscanf(buf, "SHABACK INDEX %llu %llu %*d", &shaback->index.entries,
	    &next_offset) != 2) {
		warnx("failed parsing shaback index header");
		return -1;
	}
	warnx("entries: %llu", shaback->index.entries);
	p = &buf[512];

	while (p != end) {
		e.path = NULL;
		alloc = 0;
		n = read_str_delim(p, end - p, '\0', (char **) &e.path, &alloc);
		if (n == -1)
			return -1;
		p += n;

		if (*p != '\n') {
			e.link_path = NULL;
			alloc = 0;
			n = read_str_delim(p, end - p, '\0', (char **)
			    &e.link_path, &alloc);
			if (n == -1)
				return -1;
			p += n;
			if (*p == '\n' && p != end)
				p++;
		} else if (p != end)
			p++;

		s = NULL;
		alloc = 0;

		/*
		 * TODO: use loop or one-line macro here
		 */

		/* offset */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.offset = strtoll(s, NULL, 10);

		/* type */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.type = s[0];

		/* inode */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.inode = strtoll(s, NULL, 10);

		/* ctime */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.ctime = strtoll(s, NULL, 10);

		/* atime */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.atime = strtoll(s, NULL, 10);

		/* mtime */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.mtime = strtoll(s, NULL, 10);

		/* mode */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.mode = strtoll(s, NULL, 10);

		/* uid */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.uid = strtoll(s, NULL, 10);

		/* gid */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.gid = strtoll(s, NULL, 10);

		/* size */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.size = strtoll(s, NULL, 10);

		/* compressed size */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.compressed_size = strtoll(s, NULL, 10);

		/* is_dup */
		n = read_str_delim(p, end - p, ' ', &s, &alloc);
		if (n == -1)
			break;
		p += n;
		e.is_dup = strtoll(s, NULL, 10);

		/* hash_file */
		alloc = 0;
		n = read_str_delim(p, end - p, ' ', &e.hash_file, &alloc);
		if (n == -1)
			break;
		p += n;

		/* hash_meta */
		alloc = 0;
		n = read_str_delim(p, end - p, '\n', &e.hash_meta, &alloc);
		if (n == -1)
			break;
		p += n;

		if (cb != NULL) {
			if (cb(shaback, &e) == -1)
				return -1;
		}
	}

	if (lseek(shaback->fd, next_offset, SEEK_SET) == -1)
		return -1;

	return shaback_read_index(shaback, cb);
}
