#include "shaback.h"

#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>

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
