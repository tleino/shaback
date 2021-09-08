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
#include <inttypes.h>

int
list(struct shaback *shaback, struct shaback_entry *ep)
{
	if (ep->type == 'f' && ep->is_dup == 0)
		printf("%16"PRIu64" %s\n", ep->size, ep->path);
	else if (ep->type == 'f' && ep->is_dup == 1)
		printf("DUP              %s\n", ep->path);
	else
		printf("%c                %s\n", ep->type, ep->path);

	return 0;
}

int
shaback_list(struct shaback *shaback, int argc, char **argv)
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

	if (shaback_read_index(shaback, list) == -1) {
		warn("shaback_read_index");
		close(shaback->fd);
		return -1;
	}

	close(shaback->fd);
	return 0;
}
