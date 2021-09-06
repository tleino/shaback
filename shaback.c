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

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>

#ifndef ARRLEN
#define ARRLEN(_x) sizeof((_x)) / sizeof((_x)[0])
#endif

static struct verb {
	char *verb;
	char *args;
	int min_args;
	int (*f)(struct shaback *, int, char **);
} verbs[] = {
	{ "read", "\t\tSOURCE [PATTERN ...]", 1, shaback_read },
	{ "check", "\t\tSOURCE [PATTERN ...]", 1, shaback_check },
	{ "list", "\t\tSOURCE [PATTERN ...]", 1, shaback_list },
	{ "write", "\t[-o]\tTARGET [PATTERN ...]", 1, shaback_write },
	{ "append", "\t\tTARGET [PATTERN ...]", 1, NULL },
};

static const char *prog;

static int
usage()
{
	size_t i, j;

	for (i = 0, j = 0; i < ARRLEN(verbs); i++)
		if (verbs[i].f != NULL)
			fprintf(stderr, "%-6s %s %-6s %s\n",
			    j++ == 0 ? "usage:" : "", prog,
			    verbs[i].verb, verbs[i].args);

	return 1;
}

static int
exec_verb(struct shaback *shaback, char *verb, int argc, char **argv)
{
	size_t i;

	for (i = 0; i < ARRLEN(verbs); i++)
		if (verbs[i].f != NULL &&
		    ((verbs[i].verb[0] == *verb && verb[1] == '\0') ||
		    strcmp(verbs[i].verb, verb) == 0) &&
		    argc >= verbs[i].min_args)
			return verbs[i].f(shaback, argc, argv);

	return usage();
}

int
main(int argc, char **argv)
{
	static struct shaback shaback = { 0 };

	prog = argv[0];

	if (argc < 2)
		return usage();
	else
		return exec_verb(&shaback, *(argv+1), argc-2, argv+2);
}
