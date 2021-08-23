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
	struct shaback_entry *next;	
};

struct shaback
{
	uint64_t magic;
	uint64_t entries;
	uint64_t dirs;
	uint64_t regulars;
	uint64_t symlinks;
	uint64_t time;
	uint64_t end_offset;
	uint64_t pos;
	uint64_t index_offset;
	struct shaback_entry *first;
};

int
shaback_print_entry(struct shaback *shaback, char **buf, size_t *bufsz,
    struct shaback_entry *ep)
{
	int len = 0;
	char output[SHA1_DIGEST_STRING_LENGTH];

	do {
		if (len >= *bufsz) {
			if (*bufsz == 0)
				*bufsz = 128;
			else
				*bufsz *= 2;
			*buf = realloc(*buf, *bufsz);
			if (*buf == NULL)
				return -1;
		}
		len = snprintf(*buf, *bufsz, "%llu %llu "
		    "%c %llu %llu %llu %llu %llu %llu "
		    "%llu %llu %s %s %s%s%s\n",
		    shaback->magic,
		    ep->offset, ep->type, ep->inode, ep->ctime,
		    ep->atime, ep->mtime,
		    ep->mode, ep->uid, ep->gid, ep->size,
		    ep->hash_meta, ep->hash_file, ep->path,
		    (ep->link_path == NULL) ? "" : "\n",
		    (ep->link_path == NULL) ? "" : (char *) ep->link_path);
	} while (len >= *bufsz);

	if (strcmp(ep->hash_meta, "!") == 0) {
		SHA1Data((u_int8_t *) *buf, strlen(*buf), output);
		ep->hash_meta = strdup(output);
		if (ep->hash_meta == NULL) {
			ep->hash_meta = "!";
			return -1;
		}
		return shaback_print_entry(shaback, buf, bufsz, ep);
	}

	shaback->pos += len;

	return 0;
}

int
shaback_dump_file(struct shaback *shaback, struct shaback_entry *ep)
{
	FILE *fp;
	size_t n;
	static char buf[1024 * 16];
	SHA1_CTX sha;
	u_int8_t result[SHA1_DIGEST_LENGTH] = { 0 };
	char output[SHA1_DIGEST_STRING_LENGTH] = { 0 }, *p;
	size_t i;

	fp = fopen((char *) ep->path, "r");
	if (fp == NULL)
		return -1;

	SHA1Init(&sha);

	ep->offset = shaback->pos;

	while ((n = fread(buf, sizeof(char), sizeof(buf), fp)) > 0) {
		fwrite(buf, sizeof(char), n, stdout);
		shaback->pos += n;
		SHA1Update(&sha, (u_int8_t *) buf, n);
	}
	if (ferror(fp)) {
		fclose(fp);
		return -1;
	}

	SHA1Final((u_int8_t *) result, &sha);
	p = output;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++)
		p += snprintf(p, 2 + 1, "%02x", result[i]);

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
	if (m == 512)
		return;
	for (i = 0; i < m; i++) {
		if (i == 0 || i == m - 1)
			putchar('\n');
		else
			putchar('\0');
	}
	shaback->pos += m;
}

void
shaback_add(struct shaback *shaback, const char *path)
{
	struct stat sb;
	struct shaback_entry e = { 0 }, *ep;
	ssize_t n;
	char buf[PATH_MAX + 1];

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

	/*
	 * Calculate new index offset, with padding if needed.
	 */
	if ((512 - (e.size % 512)) != 512)
		shaback->index_offset += (512 - (e.size % 512));
	shaback->index_offset += e.size;

	/*
	 * Calculate new index offset, with the added metadata.
	 */
	shaback->index_offset += 512;
}

int
main()
{
	struct shaback shaback = { 0 };
	struct shaback_entry *ep;
	FILE *fp;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	char *buf = NULL;
	size_t bufsz = 0;

	fp = fdopen(STDIN_FILENO, "r");
	if (fp == NULL)
		err(1, "fdopen %d", STDIN_FILENO);

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
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

	shaback.pos += printf("SHABACK %llu %llu %llu %llu\n",
	    shaback.magic, time(0), shaback.entries, shaback.index_offset);
	shaback_align(&shaback);

	ep = shaback.first;
	while (ep != NULL) {
		if (ep->type == 'f') {
			shaback_align(&shaback);
			if (shaback_dump_file(&shaback, ep) == 0) {
				shaback_align(&shaback);
				shaback_print_entry(&shaback, &buf, &bufsz,
				    ep);
				printf("%s", buf);
			} else
				warn("shaback_dump_file %s", ep->path);
		}
		ep = ep->next;
	}

	ep = shaback.first;
	while (ep != NULL) {
		shaback_align(&shaback);
		shaback_print_entry(&shaback, &buf, &bufsz, ep);
		printf("%s", buf);
		ep = ep->next;
	}

	fclose(fp);	
}
