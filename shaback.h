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

#ifndef SHABACK_H
#define SHABACK_H

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <sha1.h>

#include <sys/stat.h>

#define HASHMAP_ALLOC	(1024 * 1024)
#define INDEX_SIZE	(512 * 2048)

struct shaback_hash_entry
{
	size_t				 size;
	off_t				 offset;
	u_int8_t			 key[SHA1_DIGEST_LENGTH];
	struct shaback_hash_entry	*next;
};

struct shaback_entry
{
	uint8_t type;
	uint64_t ctime;
	uint64_t atime;
	uint64_t mtime;
	uint64_t mode;
	uint64_t uid;
	uint64_t gid;
	uint64_t size;
	uint64_t compressed_size;
	uint64_t inode;
	uint64_t offset;
	char *hash_meta;
	char *hash_file;
	unsigned char *path;
	unsigned char *link_path;
	u_int8_t key[SHA1_DIGEST_LENGTH];
	int is_dup;
	struct shaback_entry *next;
};

struct shaback_index {
	off_t		 offset;
	off_t		 next_offset;
	size_t		 len;
	size_t		 bytes;
	uint64_t	 entries;
	char		 buf[INDEX_SIZE];
};

struct shaback
{
	uint64_t entries;
	uint64_t dirs;
	uint64_t regulars;
	uint64_t symlinks;
	uint64_t dups;
	uint64_t time;
	uint64_t begin_offset;
	uint64_t end_offset;
	uint64_t end_offset_blocks;
	uint64_t pos;
	uint64_t index_offset;
	uint64_t index_offset_blocks;
	uint64_t index_len;
	time_t begin_time;
	uint64_t total_bytes;
	int dedup;
	int dupmeta;
	struct shaback_entry *first;
	struct shaback_hash_entry **hashmap;
	char *path;
	size_t path_alloc;
	size_t path_len;
	int fd;
	const char *target;
	unsigned char bbuf[1024 * 64];
	size_t bbuf_sz;
	struct shaback_index index;
	int n_duplicated;
	int n_compressed;
	int n_total;
	ssize_t n_bytes;
	ssize_t n_bytes_compressed;
	ssize_t n_bytes_dedup;
	int too_small_to_compress;
	int already_compressed;
};

/*
 * commands:
 *   check.c
 *   write.c
 *   read.c
 */
int				 shaback_check(struct shaback *, int, char **);
int				 shaback_write(struct shaback *, int, char **);
int				 shaback_read(struct shaback *, int, char **);

/*
 * dirwalk.c
 */
struct stat;
typedef int			(*DumpCallback)(struct shaback *, int,
				    const char *, struct stat *);

int				 shaback_dirwalk(struct shaback *,
				    int, const char *, DumpCallback);

/*
 * meta.c
 */
int				 read_meta(struct shaback *,
				    struct shaback_entry *, struct stat *);

/*
 * index.c
 */
typedef int			(*IndexCallback)(struct shaback *, struct
				    shaback_entry *);

int				 shaback_read_index(struct shaback *,
				    IndexCallback);
void				 shaback_add_index_entry(struct shaback *,
				    struct shaback_entry *);
void				 shaback_flush_index(struct shaback *);

/*
 * dedup.c
 */
int				 shaback_dedup(struct shaback *,
				    struct shaback_entry *, uint64_t);

#endif