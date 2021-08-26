#include "shaback.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
