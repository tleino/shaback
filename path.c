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
#include <assert.h>

size_t
path_hash(const char *path)
{
	const char			*p;
	size_t				 k;

	assert(path != NULL);
	k = 0;
	for (p = path; *p != '\0'; p++)
		k = *p + (k << 6) + (k << 16) - k; 

	return k % HASHMAP_ALLOC;
}

struct shaback_path_entry *
shaback_path_get(struct shaback *shaback, const char *path)
{
	size_t				 k;
	struct shaback_path_entry	*hp;

	k = path_hash(path);
	hp = shaback->path_hash[k];
	while (hp != NULL) {
		assert(hp->path != NULL);
		if (strcmp(hp->path, path) == 0)
			return hp;
		hp = hp->hash_next;
	}

	return NULL;
}

void
shaback_path_prune(struct shaback *shaback)
{
	struct shaback_entry		e = { 0 }, *ep;
	struct shaback_path_entry	*np;

	ep = &e;
	for (np = shaback->path_head; np != NULL; np = np->next) {
		if (!(np->flags & PATH_KEEP)) {
			ep->path = np->path;
			ep->type = '-';
			warnx("delete %s", ep->path);
			shaback_add_index_entry(shaback, ep);
		}
	}
}

int
shaback_path_set(struct shaback *shaback, const char *path, uint64_t mtime,
    int type)
{
	struct shaback_path_entry	*hp;
	size_t				 k;

	k = path_hash(path);

	hp = shaback->path_hash[k];
	while (hp != NULL) {
		assert(hp->path != NULL);
		if (strcmp(hp->path, path) != 0)
			hp = hp->hash_next;
		else
			break;
	}

	if (hp == NULL) {
		hp = malloc(sizeof(*hp));
		if (hp == NULL)
			return -1;

		hp->hash_next = shaback->path_hash[k];
		hp->next = shaback->path_head;

		hp->flags = 0;
		hp->mtime = mtime;
		if ((hp->path = strdup(path)) == NULL)
			return -1;

		shaback->path_hash[k] = hp;
		shaback->path_head = hp;

		if (type == PathCurrent)
			hp->flags |= (PATH_UPDATE);
	} else if (type == PathCurrent && hp->mtime < mtime) {
		hp->flags |= (PATH_UPDATE);
	}

	if (type == PathCurrent)
		hp->flags |= (PATH_KEEP);
	if (type == PathDelete)
		hp->flags &= ~(PATH_KEEP);

	return hp->flags;
}
