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

static uint64_t				 ok_bytes, fail_bytes;
static uint64_t				 ok, fail;

int
verify_hash(struct shaback *shaback, struct shaback_entry *ep)
{
	static char			 buf[CHUNK];
	ssize_t				 n;
	size_t				 sz, i;
	ssize_t				 remaining;
	SHA1_CTX			 sha;
	char				 s[SHA1_DIGEST_STRING_LENGTH]={0}, *p;

	if (ep->type != 'f' || ep->is_dup || ep->size == 0)
		return 0;

	if (lseek(shaback->fd, ep->offset, SEEK_SET) == -1) {
		warn("lseek");
		return -1;
	}

	remaining = ep->size;

	SHA1Init(&sha);
	while (remaining > 0) {
		sz = remaining < sizeof(buf) ? remaining :
		    sizeof(buf);
		if (sz != sizeof(buf))
			sz = sz/512*512+512;
		n = read(shaback->fd, buf, sz);
		if (n == -1 || n == 0)
			break;
		SHA1Update(&sha, (u_int8_t *) buf,
		    remaining < n ? remaining : n);
		remaining -= n;
	}
	SHA1Final((u_int8_t *) ep->key, &sha);

	p = s;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		p += snprintf(p, 2 + 1, "%02x", ep->key[i]);

	if (strcmp(ep->hash_file, s) != 0) {
		printf("is        : '%s'\n", s);
		printf("should be : '%s'\n", ep->hash_file);
		return -1;
	}

	return 0;
}

int
check(struct shaback *shaback, struct shaback_entry *ep)
{
	/*
	 * TODO: verify compressed files.
	 */
	if (ep->compressed_size > 0) {
		warnx("check on compressed files not supported");
		return 1;
	}

	if (verify_hash(shaback, ep) == -1) {
		warnx("fail %s", ep->path);
		fail_bytes += ep->size;
		fail++;
		return 0;
	}

	ok_bytes += ep->size;
	ok++;

	return 0;
}

static void
print_results()
{
	printf(
	    "%16llu checksum ok (files)\n"
	    "%16llu checksum ok (MBytes)\n"
	    "%16llu checksum ok (bytes)\n"
	    "%16llu checksum fail (files)\n"
	    "%16llu checksum fail (MBytes)\n"
	    "%16llu checksum fail (bytes)\n",
	    ok, ok_bytes/1024/1024, ok_bytes, fail, fail_bytes/1024/1024,
	    fail_bytes);
}

int
shaback_check(struct shaback *shaback, int argc, char **argv)
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

	if (shaback_read_index(shaback, check) == -1) {
		warn("shaback_read_index");
		close(shaback->fd);
		print_results();
		return -1;
	}

	close(shaback->fd);
	print_results();
	return 0;
}
