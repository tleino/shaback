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

/*
 * Returns 1 if duplicated, returns 0 if not duplicated, -1 if error.
 * On error, assume not duplicated.
 */
int
shaback_dedup(struct shaback *shaback, struct shaback_entry *ep,
    uint64_t numeric_key)
{
	size_t				 i, k;
	struct shaback_hash_entry	*hp;

	k = numeric_key % HASHMAP_ALLOC;

	/*
	 * Add to hashmap.
	 */
	hp = shaback->hashmap[k];
	while (hp != NULL) {
		if (hp->size == ep->size)
			for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
				if (hp->key[i] != ep->key[i])
					break;
		if (i != SHA1_DIGEST_LENGTH) {
			hp = hp->next;
		} else {
			ep->offset = hp->offset;
			ep->is_dup = 1;
			shaback->dups++;
			break;
		}
	}
	if (hp == NULL) {
		hp = malloc(sizeof(*hp));
		if (hp == NULL)
			return -1;

		hp->next = shaback->hashmap[k];
		hp->offset = ep->offset;
		hp->size = ep->size;
		memcpy(hp->key, ep->key, SHA1_DIGEST_LENGTH);

		shaback->hashmap[k] = hp;
		return 0;
	}

	return 1;
}
