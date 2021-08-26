#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>

#include <stdint.h>
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sha1.h>

#define HASHMAP_ALLOC	(1024 * 1024)

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
	uint64_t inode;
	uint64_t offset;
	char *hash_meta;
	char *hash_file;
	unsigned char *path;
	unsigned char *link_path;
	u_int8_t key[SHA1_DIGEST_LENGTH];
	int is_dup;
	struct shaback_entry *next;
	struct shaback_entry *hashmap_next;
};

struct shaback
{
	uint64_t magic;
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
	int dedup;
	int dupmeta;
	FILE *fp_out;
	char *tmp_buf;
	size_t tmp_bufsz;
	struct shaback_entry *first;
	struct shaback_entry **hashmap;
};

void				shaback_align(struct shaback *);

int
shaback_print_entry(struct shaback *shaback, char **buf, size_t *bufsz,
    struct shaback_entry *ep)
{
	int len = 0;
	char output[SHA1_DIGEST_STRING_LENGTH];
	uint64_t paths_len;
	size_t path_len, link_len;
	char *p;

	path_len = strlen((const char *) ep->path);
	if (ep->link_path != NULL)
		link_len = strlen((const char *) ep->link_path);

	do {
		if (len >= *bufsz) {
			if (*bufsz == 0)
				*bufsz = 512;
			else
				*bufsz *= 2;
			*buf = realloc(*buf, *bufsz);
			if (*buf == NULL)
				return -1;
		}

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

		len = snprintf(*buf, *bufsz, "%020llu %llu "
		    "%c %llu %llu %llu %llu %llu %llu "
		    "%llu %llu %s %s %llu\n",
		    shaback->magic,
		    ep->offset, ep->type, ep->inode, ep->ctime,
		    ep->atime, ep->mtime,
		    ep->mode, ep->uid, ep->gid, ep->size,
		    ep->hash_meta, ep->hash_file, paths_len);

		if (len + paths_len + 1 < *bufsz) {
			p = *buf;
			p += len;
			memcpy(p, ep->path, path_len + 1);
			p += path_len + 1;
			if (ep->link_path != NULL) {
				memcpy(p, ep->link_path, link_len + 1);
				p += link_len + 1;
			}
			*p++ = '\n';
			*p = '\0';
		}
		len += paths_len;
	} while (len + 1 >= *bufsz);

	if (strcmp(ep->hash_meta, "!") == 0) {
		SHA1Data((u_int8_t *) *buf, len, output);
		ep->hash_meta = strdup(output);
		if (ep->hash_meta == NULL) {
			ep->hash_meta = "!";
			return -1;
		}
		return shaback_print_entry(shaback, buf, bufsz, ep);
	}

	return len;
}

int
shaback_metadata_len(struct shaback *shaback, struct shaback_entry *ep)
{
	int r;
	int len;
	int m;

	r = shaback_print_entry(shaback, &shaback->tmp_buf,
	    &shaback->tmp_bufsz, ep);
	if (r == -1)
		return -1;

	len = strlen(shaback->tmp_buf);
	m = 512 - (len % 512);
	len += m;

	return len;
}

void
shaback_calculate_offsets(struct shaback *shaback)
{
	struct shaback_entry *ep;
	int mdlen;

	shaback->index_offset_blocks = (shaback->begin_offset / 512);
	shaback->index_offset_blocks += 1;	/* header block */
	for (ep = shaback->first; ep != NULL; ep = ep->next) {
		if (shaback->dupmeta) {
			mdlen = shaback_metadata_len(shaback, ep);
			shaback->index_offset_blocks += (mdlen / 512);
		}
		if (ep->type != 'f' || ep->is_dup)
			continue;
		shaback->index_offset_blocks += ((512 + ep->size) / 512);
	}

	shaback->end_offset_blocks = shaback->index_offset_blocks;
	for (ep = shaback->first; ep != NULL; ep = ep->next) {
		mdlen = shaback_metadata_len(shaback, ep);
		shaback->end_offset_blocks += (mdlen / 512);
	}
}

int
shaback_dump_file(struct shaback *shaback, struct shaback_entry *ep)
{
	FILE *fp;
	size_t n;
	static char buf[1024 * 16];
	SHA1_CTX sha;
	char output[SHA1_DIGEST_STRING_LENGTH] = { 0 }, *p;
	size_t i;
	struct shaback_entry *hp;
	uint64_t numeric_key;

	fp = fopen((char *) ep->path, "r");
	if (fp == NULL)
		return -1;

	SHA1Init(&sha);

	if (shaback->dedup == 0) {
		shaback_align(shaback);
		ep->offset = shaback->pos;
	}

	while ((n = fread(buf, sizeof(char), sizeof(buf), fp)) > 0) {
		if (shaback->dedup == 0) {
			fwrite(buf, sizeof(char), n, shaback->fp_out);
			shaback->pos += n;
		}
		SHA1Update(&sha, (u_int8_t *) buf, n);
	}
	if (ferror(fp)) {
		fclose(fp);
		return -1;
	}

	SHA1Final((u_int8_t *) ep->key, &sha);
	p = output;
	numeric_key = 0;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		p += snprintf(p, 2 + 1, "%02x", ep->key[i]);
		numeric_key ^= (ep->key[i] << (i * 2));
	}

	/*
	 * Add to hashmap.
	 */
	if (shaback->dedup == 1) {
		hp = shaback->hashmap[numeric_key % HASHMAP_ALLOC];
		while (hp != NULL) {
			for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
				if (hp->key[i] != ep->key[i])
					break;
			if (i != SHA1_DIGEST_LENGTH) {
				hp = hp->hashmap_next;
			} else {
				ep->offset = hp->offset;
				ep->is_dup = 1;
				shaback->dups++;
				break;
			}
		}
		if (hp == NULL) {
			ep->hashmap_next =
			    shaback->hashmap[numeric_key % HASHMAP_ALLOC];
			shaback->hashmap[numeric_key % HASHMAP_ALLOC] = ep;

			if (fseek(fp, 0, SEEK_SET) == -1)
				err(1, "fseek");

			shaback_align(shaback);
			ep->offset = shaback->pos;

			while ((n = fread(buf, sizeof(char),
			    sizeof(buf), fp)) > 0) {
				fwrite(buf, sizeof(char), n,
				    shaback->fp_out);
				shaback->pos += n;
			}
			if (ferror(fp)) {
				fclose(fp);
				return -1;
			}
		}
	}

	ep->hash_file = strdup((const char *) output);
	if (ep->hash_file == NULL) {
		ep->hash_file = "!";
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

void
shaback_align(struct shaback *shaback)
{
	uint64_t m;
	uint64_t i;

	m = 512 - (shaback->pos % 512);
	for (i = 0; i < m; i++)
		fputc('\0', shaback->fp_out);
	shaback->pos += m;
}

void
shaback_add(struct shaback *shaback, const char *path)
{
	struct stat sb;
	struct shaback_entry e = { 0 }, *ep;
	ssize_t n;
	char buf[PATH_MAX + 1];
	int len;

	if (lstat(path, &sb) != 0) {
		warn("lstat %s", path);
		return;
	}

	if (S_ISDIR(sb.st_mode)) {
		shaback->dirs++;
		e.type = 'd';
	} else if (S_ISLNK(sb.st_mode)) {
		shaback->symlinks++;
		e.type = 'l';
		n = readlink(path, buf, sizeof(buf) - 1);
		if (n <= 0)
			warn("readlink %s", path);
		else {
			buf[n] = '\0';
			e.link_path = (unsigned char *) strdup(buf);
		}
	} else if (S_ISREG(sb.st_mode)) {
		shaback->regulars++;
		e.type = 'f';
	} else {
		warnx("%s: unsupported file type", path);
		return;
	}

	e.inode = sb.st_ino;
	e.ctime = sb.st_ctim.tv_sec;
	e.mtime = sb.st_mtim.tv_sec;
	e.atime = sb.st_atim.tv_sec;
	e.uid = sb.st_uid;
	e.gid = sb.st_gid;
	e.size = sb.st_size;
	e.path = (unsigned char *) strdup(path);
	if (e.path == NULL) {
		warn("strdup %s", path);
		return;
	}

	e.hash_meta = "!";
	e.hash_file = "!";

	ep = malloc(sizeof(struct shaback_entry));
	if (ep == NULL) {
		warn("malloc shaback_entry %s", path);
		return;
	}
	*ep = e;

	ep->next = shaback->first;
	shaback->first = ep;
	shaback->entries++;

	if (e.type == 'f') {

		/*
		 * Calculate new index offset, with padding if needed.
		 */
		shaback->index_offset += (512 - (e.size % 512));
		shaback->index_offset += e.size;
	}

	/*
	 * Calculate new index offset, with the added metadata.
	 */
	len = shaback_metadata_len(shaback, ep);
	if (len == -1)
		err(1, "shaback_metadata_len");

	if (e.type == 'f')
		shaback->index_offset += len;

	shaback->index_len += len;
}

void
shaback_test(struct shaback *shaback)
{
	size_t n, i;
	struct shaback_entry e = { 0 }, *ep;
	uint64_t magic;
	uint64_t paths_len;
	uint64_t entries;
	char hash_meta[SHA1_DIGEST_STRING_LENGTH];
	char hash_file[SHA1_DIGEST_STRING_LENGTH];
	static char buf[1024 * 64];
	SHA1_CTX sha;
	char output[SHA1_DIGEST_STRING_LENGTH] = { 0 }, *p;
	static uint64_t len;
	size_t nmemb;
	uint64_t index_bytes, data_bytes;
	char *path = NULL;
	size_t pathsz = 0;
	ssize_t pathlen;
	char *meta = NULL;
	size_t metasz = 0;
	ssize_t metalen;
	int v;

	if (fseeko(shaback->fp_out, shaback->index_offset, SEEK_SET) == -1)
		err(1, "fseeko");

	entries = 0;
	warnx("reading metadata...");
	index_bytes = 0;
	while ((metalen = getline(&meta, &metasz, shaback->fp_out)) != -1) {
		index_bytes += metalen;
		if (ferror(shaback->fp_out))
			warn("fread");
		if ((v = sscanf(meta, "%llu "
		    "%llu %c "
		    "%llu %llu %llu %llu %llu "
		    "%llu %llu %llu "
		    "%s %s %llu",
		    &magic,
		    &e.offset, &e.type,
		    &e.inode, &e.ctime, &e.atime, &e.mtime, &e.mode,
		    &e.uid, &e.gid, &e.size,
		    hash_meta, hash_file, &paths_len)) != 14) {
			warnx("bogus metadata at offset %llu",
			    ftello(shaback->fp_out));
			break;
		}

		if (ferror(shaback->fp_out))
			warn("fread");

		pathlen = getdelim(&path, &pathsz, '\0', shaback->fp_out);
		if (pathlen != -1)
			e.path = (unsigned char *) strdup(path);
		else
			warn("getdelim");
		if (e.type == 'l') {
			pathlen = getdelim(&path, &pathsz, '\0',
			    shaback->fp_out);
			if (pathlen != -1)
				e.link_path = (unsigned char *) strdup(path);
			else
				warn("getdelim");
		}
		index_bytes += paths_len;

		/*
		 * Seek to end of the block.
		 */
		index_bytes += (512 - (index_bytes % 512));
		if (fseeko(shaback->fp_out,
		    (shaback->index_offset + index_bytes),
		    SEEK_SET) == -1)
			err(1, "fseeko");

		if (ferror(shaback->fp_out))
			warn("getdelim");

		e.hash_file = strdup(hash_file);
		e.hash_meta = strdup(hash_meta);
		if (e.hash_file == NULL || e.hash_meta == NULL)
			warn("strdup");

		if (magic != shaback->magic) {
			warnx("magic did not magic");
			break;
		}

		ep = malloc(sizeof(struct shaback_entry));
		if (ep == NULL) {
			warn("malloc shaback_entry %s", e.path);
			return;
		}
		*ep = e;
		ep->next = shaback->first;
		shaback->first = ep;
		entries++;
	}
	if (ferror(shaback->fp_out))
		warn("getline");
	free(meta);
	free(path);

	warnx("reading data...");

	data_bytes = 0;
	for (ep = shaback->first; ep != NULL; ep = ep->next) {
		entries--;
		if (ep->type != 'f')
			continue;

		if (fseeko(shaback->fp_out, ep->offset, SEEK_SET) == -1)
			warn("fseeko");

		SHA1Init(&sha);

		len = ep->size;
		nmemb = (len < sizeof(buf) ? len : sizeof(buf));
		while (len > 0 && (n = fread(buf, sizeof(char), nmemb,
		    shaback->fp_out)) > 0) {
			data_bytes += n;
			SHA1Update(&sha, (u_int8_t *) buf, n);
			len -= n;
			nmemb = (len < sizeof(buf) ? len : sizeof(buf));
		}
		if (ferror(shaback->fp_out)) {
			fclose(shaback->fp_out);
			return;
		}

		SHA1Final((u_int8_t *) ep->key, &sha);
		p = output;
		for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
			p += snprintf(p, 2 + 1, "%02x", ep->key[i]);
		}
		if (strcmp(output, ep->hash_file) != 0) {
			printf("FAIL inode=%llu offset=%llu size=%llu "
			   "%s %s\n",
			    ep->inode, ep->offset, ep->size, ep->path,
			    hash_file);
		}
	}

	warnx("test complete, entries %llu, %llu entries left",
	    shaback->entries, entries);
	warnx("%llu MBytes index, %llu MBytes data, %llu MBytes total",
	    index_bytes / 1024 / 1024, data_bytes / 1024 / 1024,
	    (index_bytes + data_bytes) / 1024 / 1024);

	exit(0);
}

void
usage(const char *prog)
{
	fprintf(stderr,
	    "Usage: %s [-adDt0] -w <file>\n", prog);
}

int
main(int argc, char **argv)
{
	struct shaback shaback = { 0 };
	struct shaback shaprev = { 0 };
	struct shaback_entry *ep;
	FILE *fp;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	char *buf = NULL;
	size_t bufsz = 0;
	int ch, want_append;
	char *file = NULL;
	int delim;
	int len;
	int want_test;

	want_append = 0;
	want_test = 0;
	delim = '\n';
	shaback.dupmeta = 1;
	while ((ch = getopt(argc, argv, "tadDw:0")) != -1) {
		switch (ch) {
		case 'a':
			want_append ^= 1;
			break;
		case 'd':
			shaback.dedup ^= 1;
			break;
		case 'D':
			shaback.dupmeta ^= 1;
			break;
		case 't':
			want_test ^= 1;
			break;
		case 'w':
			if (optarg[0] == '-' && optarg[1] == '\0') {
				shaback.fp_out = fdopen(STDOUT_FILENO, "w");
				if (shaback.fp_out == NULL)
					err(1, "fdopen");
			} else if (optarg[0] != '\0') {
				file = strdup(optarg);
			}
			break;
		case '0':	/* Use the NUL as a pathname delimeter */
			delim = '\0';
			break;
		}
	}

	if (shaback.dedup) {
		shaback.hashmap = calloc(HASHMAP_ALLOC,
		    sizeof(struct shaback_entry *));
		if (shaback.hashmap == NULL)
			err(1, "calloc");
	}

	if (want_append || want_test) {
		if (shaback.fp_out != NULL &&
		    fileno(shaback.fp_out) == STDOUT_FILENO)
			errx(1, "-a not compatible with -w -");

		shaback.fp_out = fopen(file, want_test ? "r+" : "r");
		if (shaback.fp_out == NULL)
			err(1, "%s", file);

		while (fscanf(shaback.fp_out,
		    "%*s %llu %llu %llu %llu %llu %llu %*llu %*llu %*llu",
		    &shaprev.magic, &shaprev.begin_time, &shaprev.entries,
		    &shaprev.begin_offset,
		    &shaprev.index_offset, &shaprev.end_offset) == 6) {
			warnx("found previous backup of %llu blocks "
			    "at block %llu",
			    (shaprev.end_offset - shaprev.begin_offset) / 512,
			    shaprev.begin_offset / 512);
			if (ferror(shaback.fp_out) || feof(shaback.fp_out))
				warn("fscanf");

			if (want_test) {
				shaprev.fp_out = shaback.fp_out;
				shaback_test(&shaprev);
			}

			if (fseeko(shaback.fp_out, shaprev.end_offset,
			    SEEK_SET) == -1)
				err(1, "fseeko");
		}
		shaback.begin_offset = shaprev.end_offset;
	} else if (shaback.fp_out == NULL) {
		shaback.fp_out = fopen(file, "w");
		if (shaback.fp_out == NULL)
			err(1, "%s", file);
	}

	if (shaback.fp_out == NULL) {
		usage(argv[0]);
		return 1;
	}

	argc -= optind;
	argv += optind;

	fp = fdopen(STDIN_FILENO, "r");
	if (fp == NULL)
		err(1, "fdopen %d", STDIN_FILENO);

	shaback.begin_time = time(0);

	while ((linelen = getdelim(&line, &linesize, delim, fp)) != -1) {
		if (delim != '\0')
			line[strcspn(line, "\r\n")] = '\0';
		shaback_add(&shaback, line);
		fprintf(stderr, "\r%llu", shaback.entries);
	}
	free(line);
	if (ferror(fp))
		err(1, "getline");

	shaback.index_offset += 512;

	fprintf(stderr, "\r%llu dirs, %llu files, %llu symlinks, %llu MB\n",
	    shaback.dirs, shaback.regulars, shaback.symlinks,
	    shaback.index_offset / 1024 / 1024);

	arc4random_buf(&shaback.magic, sizeof(uint64_t));

	shaback.pos += fprintf(shaback.fp_out, "SHABACK\n");

	ep = shaback.first;
	for (ep = shaback.first; ep != NULL; ep = ep->next) {
		if (ep->type == 'f' && shaback_dump_file(&shaback, ep) != 0)
			warn("shaback_dump_file %s", ep->path);
		if (shaback.dupmeta) {
			shaback_align(&shaback);
			len = shaback_print_entry(&shaback, &buf, &bufsz, ep);
			if (len == -1)
				err(1, "shaback_print_entry");
			shaback.pos += len;
			fwrite(buf, sizeof(char), len, shaback.fp_out);
		}
	}

	if (shaback.dedup)
		fprintf(stderr, "%llu dups\n", shaback.dups);

	ep = shaback.first;
	while (ep != NULL) {
		shaback_align(&shaback);
		len = shaback_print_entry(&shaback, &buf, &bufsz, ep);
		if (len == -1)
			err(1, "shaback_print_entry");
		shaback.pos += len;
		fwrite(buf, sizeof(char), len, shaback.fp_out);
		ep = ep->next;
	}
	shaback_align(&shaback);

	if (fseeko(shaback.fp_out, shaback.begin_offset, SEEK_SET) == -1)
		warn("fseeko");

	warnx("calculating offsets");
	shaback_calculate_offsets(&shaback);
	warnx("done");
	shaback.pos = fprintf(shaback.fp_out,
	    "SHABACK %020llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
	    shaback.magic,
	    shaback.begin_time,
	    shaback.entries,
	    shaback.begin_offset,
	    shaback.index_offset_blocks * 512,
	    shaback.end_offset_blocks * 512,
	    shaback.begin_offset / 512,
	    shaback.index_offset_blocks,
	    shaback.end_offset_blocks);
	shaback_align(&shaback);

	fclose(fp);
	fclose(shaback.fp_out);
	return 0;
}
