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
#ifdef __linux__
#include <strings.h>
#endif
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <zlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <ctype.h>

static int				 write_blocks(struct shaback *,
					    const char *, size_t);
static int				 pad_blocks(struct shaback *);

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
	static char			 buf[CHUNK];
	SHA1_CTX			 sha;
	char				 s[SHA1_DIGEST_STRING_LENGTH]={0}, *p;
	uint64_t			 nkey;
	off_t				 orig_offset;
	int				 flushes;
	off_t				 orig_pos;
	size_t				 orig_bbuf_sz;

	orig_pos = shaback->pos;
	orig_bbuf_sz = shaback->bbuf_sz;

	ep->offset = shaback->pos + shaback->bbuf_sz;

	SHA1Init(&sha);

	total = 0;
	flushes = 0;
	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		SHA1Update(&sha, (u_int8_t *) buf, n);

		if (shaback->dedup_overwrite) {
			total += n;
			flushes += write_blocks(shaback, buf, n);
			if (flushes == -1)
				return -1;
		}
	}
	SHA1Final((u_int8_t *) ep->key, &sha);
	if (n < 0)
		return -1;

	p = s;
	nkey = 0;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		p += snprintf(p, 2 + 1, "%02x", ep->key[i]);
		nkey = ep->key[i] + (nkey << 6) + (nkey << 16) - nkey; 
	}

	ep->hash_file = strdup((const char *) s);
	if (ep->hash_file == NULL) {
		ep->hash_file = "!";
		return -1;
	}

	shaback->n_total++;

	orig_offset = ep->offset;
	if (shaback->dedup_overwrite &&
	    shaback_dedup(shaback, ep, nkey) == 1) {
		shaback->n_duplicated++;
		shaback->n_bytes_dedup -= ep->size;
		shaback->n_bytes += ep->size;

		/*
		 * If we have already flushed, the data that was
		 * buffered prior to this file should be written out
		 * so that we can simply discard any content in the
		 * buffer we may have about this file.
		 *
		 * Otherwise, we need to reset the buffer back to
		 * how it looked before attempting to write this
		 * duplicated file.
		 */
		if (flushes > 0) {
			shaback->bbuf_sz = 0;
			shaback->pos = orig_offset;
			if (lseek(shaback->fd, orig_offset, SEEK_SET) == -1)
				return -1;
		} else {
			shaback->bbuf_sz = orig_bbuf_sz;
			shaback->pos = orig_pos;
		}
		total -= ep->size;
	} else if (shaback->dedup_overwrite) {
		shaback->n_bytes += ep->size;
		pad_blocks(shaback);

		if (total != ep->size) {
			warnx("adjust size %s", ep->path);
			ep->size = total;
		}
	} else if (!shaback->dedup_overwrite &&
	    shaback_dedup(shaback, ep, nkey) == 0) {
		int			 ret, flush;
		unsigned int		 have;
		z_stream		 strm;
		int			 want;
		static unsigned char	 out[CHUNK];
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
					strm.avail_out = CHUNK;
					strm.next_out = out;

					ret = deflate(&strm, flush);
					if (ret == Z_STREAM_ERROR) {
						warnx("compress error");
						break;
					}
					have = (CHUNK) - strm.avail_out;

					total_out += have;
					ep->compressed_size += have;
					if (write_blocks(shaback, out, have)
					    == -1) {
						pad_blocks(shaback);
						return -1;
					}
				} while (strm.avail_out == 0);
			} while (flush != Z_FINISH);
			deflateEnd(&strm);
			shaback->n_bytes_compressed += (total_out - ep->size);
		} else {
			while ((n = read(fd, buf, sizeof(buf))) > 0) {
				total += n;
				if (write_blocks(shaback, buf, n) == -1) {
					pad_blocks(shaback);
					return -1;
				}
			}
		}

		shaback->n_bytes += ep->size;
		pad_blocks(shaback);

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

int
shaback_flush_blocks(struct shaback *shaback)
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
pad_blocks(struct shaback *shaback)
{
	static char buf[512];
	int m;

	/*
	 * This is purely for cosmetic reasons.
	 */
	memset(buf, '\0', 512);

	m = (shaback->bbuf_sz / 512 * 512) - shaback->bbuf_sz;
	if (m < 0)
		m += 512;
	if (m != 0)
		return write_blocks(shaback, buf, m);
	return 0;
}

/*
 * Returns flushed count or -1 if we got error when flushing.
 */
static int
write_blocks(struct shaback *shaback, const char *buf, size_t bsz)
{
	char *p;
	size_t remaining, len;
	size_t orig_bsz;
	int flushes = 0;

	orig_bsz = bsz;	

	while (bsz) {
		if (shaback->bbuf_sz == sizeof(shaback->bbuf)) {
			if (shaback_flush_blocks(shaback) == -1)
				return -1;
			flushes++;
		}

		remaining = sizeof(shaback->bbuf) - shaback->bbuf_sz;
		p = &shaback->bbuf[shaback->bbuf_sz];
		len = remaining < bsz ? remaining : bsz;
		memcpy(p, &buf[orig_bsz - bsz], remaining < bsz ? remaining : bsz);
		bsz -= len;
		shaback->bbuf_sz += len;
	}

	return flushes;
}

static int
dump(struct shaback *shaback, int fd, const char *path, struct stat *sb)
{
	struct shaback_entry		 e = {0}, *ep;
	size_t				 curpos = 0;
	int				 flags;

	ep = &e;

	if ((ep->path = strdup(path)) == NULL) {
		return -1;
	}

	if (read_meta(shaback, ep, sb) == -1) {
		warn("read_meta");
		free(ep->path);
		return -1;
	}

	flags = shaback_path_set(shaback, ep->path, ep->mtime, PathCurrent);
	if (flags == -1) {
		free(ep->path);
		return -1;
	}
	else if (!(flags & PATH_UPDATE)) {
		free(ep->path);
		return 0;
	}

	if (S_ISREG(sb->st_mode) && ep->size > 0) {
		if (shaback_dump_file(shaback, fd, ep) == -1) {
			free(ep->path);
			return -1;
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
load_index(struct shaback *shaback, struct shaback_entry *ep)
{
	uint64_t			 nkey;
	char				*p;
	int				 nibble, num, j;

	/*
	 * If index says a file is deleted, we don't load that entry.
	 */
	if (ep->type == '-') {
		if (shaback_path_set(shaback, ep->path, ep->mtime, PathDelete)
		    == -1)
			return -1;
		return 0;
	}

	if (shaback_path_set(shaback, ep->path, ep->mtime, PathStored) == -1)
		return -1;

	if (ep->type != 'f' || ep->size == 0)
		return 0;

	nkey = 0;
	p = ep->hash_file;
	nibble = 0;
	j = 0;
	while (p != NULL && *p != '\0') {
		if (*p >= '0' && *p <= '9')
			num = (*p - '0');
		else if (*p >= 'a' && *p <= 'f')
			num = (*p - 'a' + 10);
		else
			break;

		if (nibble++ == 1) {
			ep->key[j] += num;
			nkey = ep->key[j] + (nkey << 6) + (nkey << 16) - nkey; 
			j++;
			nibble = 0;
		} else
			ep->key[j] = num * 16;

		p++;
	}
	if (shaback_dedup(shaback, ep, nkey) == -1)
		return -1;

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
			case 'f':
				printf("Force full backup\n");
				shaback->force_full = 1;
				break;
			default:
				fprintf(stderr, "Supported options: -foz\n");
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

	if (shaback->force_full == 0) {
		if ((shaback->fd = open(shaback->target, O_RDONLY, 0)) == -1) {
			warn("%s", shaback->target);
			goto full_backup;
		}

		printf("Reading previous backup...\n");
		if (shaback_read_index(shaback, load_index) == -1) {
			warn("shaback_read_index");
			close(shaback->fd);
		}
		printf("%"PRIu64" entries (%"PRIu64" dups)\n", shaback->entries,
		    shaback->dups);

		close(shaback->fd);

		if ((shaback->fd = open(shaback->target,
		    O_WRONLY | O_CREAT,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
		    S_IROTH | S_IWOTH)) == -1) {
			warn("%s", shaback->target);
			return -1;
		}
	} else {
full_backup:
#ifdef __OpenBSD__
		shaback->magic = (uint64_t) arc4random();
#else
		srand(getpid());
		shaback->magic = (uint64_t) rand();
#endif
		printf("full backup\n");
		if (shaback->force_full == 0) {
			printf("Are you sure? ");
			fflush(stdout);
			if (tolower(getchar()) != 'y') {
				warnx("aborted");
				return -1;
			}
		}
		if ((shaback->fd = open(shaback->target,
		    O_WRONLY | O_CREAT | O_TRUNC,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
		    S_IROTH | S_IWOTH)) == -1) {
			warn("%s", shaback->target);
			return -1;
		}
	}

	/*
	 * Reserve space for the index.
	 */
	shaback->pos = shaback->index.next_offset + INDEX_SIZE;
	printf("Seeking to pos %"PRIu64"\n", shaback->pos);
	if (lseek(shaback->fd, shaback->pos, SEEK_SET) == -1)
		err(1, "lseek");
	shaback->index.offset = shaback->index.next_offset;
	shaback->index.len = 512;
	shaback->index.entries = 0;

	if (argc == 0) {
		arg1[argc++] = ".";
		args = arg1;
	} else
		args = argv;

	for (i = 0; i < argc; i++) {
		printf("Dirwalking and dumping: %s\n", args[i]);
		ret = shaback_dirwalk(shaback, AT_FDCWD, args[i], dump);
		if (ret == -1)
			warn("%s", args[i]);
	}

	printf("Pruning index\n");
	shaback_path_prune(shaback);

	printf("Flushing index\n");
	if (shaback->index.entries == 0)
		printf("...0 entries, no need to flush\n");
	else
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
