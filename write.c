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

static int				 write_blocks(struct shaback *,
					    const char *, size_t);
static int				 flush_blocks(struct shaback *);

static int
shaback_want_compress(struct shaback *shaback, struct shaback_entry *ep)
{
	const char			*p;

	if (!shaback->compress)
		return 0;

	if (ep->size < 1024) {
		shaback->too_small_to_compress++;
		return 0;
	}

	p = strrchr(ep->path, '.');
	if (p == NULL)
		return 1;
	p++;

	if (strcasecmp(p, "gz") == 0 || strcasecmp(p, "Z") == 0 ||
	    strcasecmp(p, "bz2") == 0 || strcasecmp(p, "tgz") == 0 ||
	    strcasecmp(p, "zip") == 0 || strcasecmp(p, "aac") == 0 ||
	    strcasecmp(p, "mp4") == 0 || strcasecmp(p, "jpg") == 0 ||
	    strcasecmp(p, "gif") == 0 || strcasecmp(p, "png") == 0 ||
	    strcasecmp(p, "cr2") == 0 || strcasecmp(p, "dng") == 0 ||
	    strcasecmp(p, "flac") == 0) {
		shaback->already_compressed++;
		return 0;
	}

	return 1;
}

static int
shaback_dump_file(struct shaback *shaback, int fd, struct shaback_entry *ep)
{
	ssize_t				 n;
	size_t				 total, i;
	static char			 buf[1024 * 64];
	SHA1_CTX			 sha;
	char				 s[SHA1_DIGEST_STRING_LENGTH]={0}, *p;
	uint64_t			 numeric_key;
	off_t				 orig_offset;

	ep->offset = shaback->pos;

	SHA1Init(&sha);

	total = 0;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		SHA1Update(&sha, (u_int8_t *) buf, n);

		if (shaback->dedup_overwrite) {
			total += n;
			if (write_blocks(shaback, buf, n) == -1)
				return -1;
		}
	}
	SHA1Final((u_int8_t *) ep->key, &sha);
	if (shaback->dedup_overwrite) {
		shaback->n_bytes += ep->size;
		flush_blocks(shaback);

		if (total != ep->size) {
			warnx("adjust size %s", ep->path);
			ep->size = total;
		}
	}
	if (n < 0)
		return -1;

	p = s;
	numeric_key = 0;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		p += snprintf(p, 2 + 1, "%02x", ep->key[i]);
		numeric_key ^= (ep->key[i] << (i * 2));
	}

	ep->hash_file = strdup((const char *) s);
	if (ep->hash_file == NULL) {
		ep->hash_file = "!";
		return -1;
	}

	shaback->n_total++;

	orig_offset = ep->offset;
	if (shaback->dedup_overwrite &&
	    shaback_dedup(shaback, ep, numeric_key) == 1) {
		total -= ep->size;
		shaback->n_duplicated++;
		shaback->n_bytes_dedup -= ep->size;
		shaback->n_bytes += ep->size;
		if (lseek(shaback->fd, orig_offset, SEEK_SET) == -1)
			return -1;
		shaback->pos = orig_offset;
	} else if (!shaback->dedup_overwrite &&
	    shaback_dedup(shaback, ep, numeric_key) == 0) {
		int			 ret, flush;
		unsigned int		 have;
		z_stream		 strm;
		int			 want;
		unsigned char		 out[1024 * 64];
		size_t			 total_out;

		want = shaback_want_compress(shaback, ep);

		if (lseek(fd, 0, SEEK_SET) == -1) {
			warn("lseek");
			return 0;
		}

		total = 0;
		if (want) {
			strm.zalloc = Z_NULL;
			strm.zfree = Z_NULL;
			strm.opaque = Z_NULL;
			ret = deflateInit(&strm, 1 /*Z_DEFAULT_COMPRESSION */);
			if (ret != Z_OK)
				want = 0;
		}
		if (want) {
			shaback->n_compressed++;
			total_out = 0;
			do {
				n = read(fd, buf, sizeof(buf));
				if (n == -1) {
					warn("read");
					break;
				}
				total += n;

				strm.avail_in = n;
				strm.next_in = buf;
				flush = (n == 0) ? Z_FINISH : Z_NO_FLUSH;

				do {
					strm.avail_out = 1024 * 64;
					strm.next_out = out;

					ret = deflate(&strm, flush);
					if (ret == Z_STREAM_ERROR) {
						warnx("compress error");
						break;
					}
					have = (1024 * 64) - strm.avail_out;

					total_out += have;
					ep->compressed_size += have;
					if (write_blocks(shaback, out, have)
					    == -1)
						return -1;
				} while (strm.avail_out == 0);
			} while (flush != Z_FINISH);
			deflateEnd(&strm);
			shaback->n_bytes_compressed += (total_out - ep->size);
		} else {
			while ((n = read(fd, buf, sizeof(buf))) > 0) {
				total += n;
				if (write_blocks(shaback, buf, n) == -1)
					return -1;
			}
		}

		shaback->n_bytes += ep->size;
		flush_blocks(shaback);

		if (total != ep->size) {
			warnx("adjust size %s", ep->path);
			ep->size = total;
		}
	} else if (!shaback->dedup_overwrite) {
		shaback->n_duplicated++;
		shaback->n_bytes_dedup -= ep->size;
		shaback->n_bytes += ep->size;
	}

	return (n == -1) ? -1 : total;
}

static int
flush_blocks(struct shaback *shaback)
{
	size_t			 off;
	ssize_t			 nw;
	size_t			 bsz;

	if (shaback->bbuf_sz != sizeof(shaback->bbuf)) {
		bsz = shaback->bbuf_sz;
		if (bsz % 512 != 0)
			bsz = ((bsz/512) * 512) + 512;

		/*
		 * This memset here is purely for cosmetic reasons.
		 */
		memset(&shaback->bbuf[shaback->bbuf_sz], '\0',
		    bsz - shaback->bbuf_sz);
	} else {
		bsz = sizeof(shaback->bbuf);
	}

	for (off = 0; off < bsz; off += nw)
		if ((nw = write(shaback->fd, shaback->bbuf + off,
		    bsz - off)) == 0 ||
		    nw == -1) {
			warn("%s bsz: %zu off %zu nw %zd", shaback->target,
			    bsz, off, nw);
			errno = 0;
			return -1;
		}

	shaback->pos += bsz;
	shaback->bbuf_sz = 0;
	return 0;
}

static int
write_blocks(struct shaback *shaback, const char *buf, size_t bsz)
{
	char *p;
	size_t remaining, len;
	size_t orig_bsz;

	orig_bsz = bsz;	

	while (bsz) {
		if (shaback->bbuf_sz == sizeof(shaback->bbuf))
			flush_blocks(shaback);
		remaining = sizeof(shaback->bbuf) - shaback->bbuf_sz;
		p = &shaback->bbuf[shaback->bbuf_sz];
		len = remaining < bsz ? remaining : bsz;
		memcpy(p, buf, remaining < bsz ? remaining : bsz);
		bsz -= len;
		shaback->bbuf_sz += len;
	}

	return orig_bsz;
}

static int
dump(struct shaback *shaback, int fd, const char *path, struct stat *sb)
{
	struct shaback_entry e = {0}, *ep;
	size_t curpos = 0;

	ep = &e;

	if ((ep->path = strdup(path)) == NULL) {
		return -1;
	}

	if (read_meta(shaback, ep, sb) == -1) {
		warn("read_meta");
		free(ep->path);
		return -1;
	}

	if (S_ISREG(sb->st_mode) && ep->size > 0) {
		if (shaback_dump_file(shaback, fd, ep) == -1) {
			free(ep->path);
			free(ep);
			return 1;
		}

		curpos = shaback->pos;
	}

	shaback_add_index_entry(shaback, ep);
	free(ep->path);

	if (ep->link_path)
		free(ep->link_path);
	if (ep->hash_file != NULL && *ep->hash_file != '!')
		free(ep->hash_file);
	if (ep->hash_meta != NULL && *ep->hash_meta != '!')
		free(ep->hash_meta);

	shaback->entries++;

	return 0;
}

int
shaback_write(struct shaback *shaback, int argc, char **argv)
{
	size_t i;
	int ret;
	char *arg1[1], **args;
	char *p;

	if (**argv == '-' && argc > 1) {
		p = *argv;
		while (*++p != '\0') {
			switch (*p) {
			case 'o':
				printf("Dedupping by overwriting\n");
				shaback->dedup_overwrite = 1;
				break;
			case 'z':
				printf("Compress\n");
				shaback->compress = 1;
				break;
			default:
				fprintf(stderr, "Supported options: -oz\n");
				break;
			}
		}
		argv++;
		argc--;
	}

	shaback->target = *argv++;
	argc--;

	if (1 || shaback->dedup) {
		shaback->hashmap = calloc(HASHMAP_ALLOC,
		    sizeof(struct shaback_hash_entry *));
		if (shaback->hashmap == NULL)
			err(1, "calloc");
	}

	if ((shaback->fd = open(shaback->target,
	    O_WRONLY | O_CREAT | O_TRUNC,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)) == -1) {
		warn("%s", shaback->target);
		return -1;
	}

	/*
	 * Reserve space for the index.
	 */
	shaback->pos = INDEX_SIZE;
	if (lseek(shaback->fd, INDEX_SIZE, SEEK_SET) == -1)
		err(1, "lseek");
	shaback->index.offset = 0;
	shaback->index.len = 512;

	if (argc == 0) {
		arg1[argc++] = ".";
		args = arg1;
	} else
		args = argv;

	for (i = 0; i < argc; i++) {
		ret = shaback_dirwalk(shaback, AT_FDCWD, args[i], dump);
		if (ret == -1)
			warn("%s", args[i]);
	}

	shaback_flush_index(shaback);

	printf("%16zd\tactual (KB)\n"
	    "%16zd\tcompress (KB)\n%16zd\tdedup (KB)\n%16zd\tfinal (KB)\n"
	    "%16d\tdups\n"
	    "%16d\tcompressed\n"
	    "%16d\ttoo small to compress\n"
	    "%16d\talready compressed\n"
	    "%16d\ttotal\n",
	    shaback->n_bytes / 1024,
	    shaback->n_bytes_compressed / 1024,
	    shaback->n_bytes_dedup / 1024,
	    (shaback->n_bytes + shaback->n_bytes_compressed +
	    shaback->n_bytes_dedup) / 1024,
	    shaback->n_duplicated,
	    shaback->n_compressed,
	    shaback->too_small_to_compress,
	    shaback->already_compressed,
	    shaback->n_total);

	close(shaback->fd);

	return ret;
}
