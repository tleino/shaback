#include "shaback.h"

#include <err.h>
#include <string.h>
#include <stdlib.h>

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
