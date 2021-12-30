/*
  Copyright (c) 2015-2016, Apple Inc. All rights reserved.

  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

  1.  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

  2.  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
  in the documentation and/or other materials provided with the distribution.

  3.  Neither the name of the copyright holder(s) nor the names of any contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include "lzfse.h"
#include <fcntl.h>
#include <stdio.h>

#include <linux/string.h>
#include <sys/stat.h>
#include <sys/types.h>


void usage(int argc, char **argv) {
	fprintf(
		stderr,
		"Usage: %s -encode|-decode [-i input_file] [-o output_file] [-h] [-v]\n",
		argv[0]);
}

#define USAGE(argc, argv)			\
	do {					\
		usage(argc, argv);		\
		exit(0);			\
	} while (0)
#define USAGE_MSG(argc, argv, ...)		\
	do {					\
		usage(argc, argv);		\
		fprintf(stderr, __VA_ARGS__);	\
		exit(1);			\
	} while (0)


#define PAGE_SIZE 4096

enum { LZFSE_ENCODE = 0, LZFSE_DECODE };

int
main(int argc, char **argv)
{
	const char *in_file = 0;  // stdin
	const char *out_file = 0; // stdout
	int op = -1;              // invalid op
	int i;
	// Parse options
	for (i = 1; i < argc;) {
		// no args
		const char *a = argv[i++];

		if (strcmp(a, "-encode") == 0) {
			op = LZFSE_ENCODE;
			continue;
		}
		if (strcmp(a, "-decode") == 0) {
			op = LZFSE_DECODE;
			continue;
		}

		// one arg
		const char **arg_var = 0;
		if (strcmp(a, "-i") == 0 && in_file == 0)
			arg_var = &in_file;
		else if (strcmp(a, "-o") == 0 && out_file == 0)
			arg_var = &out_file;
		if (arg_var != 0) {
			// Flag is recognized. Check if there is an argument.
			if (i == argc)
				fprintf(stderr, "Error: Missing arg after %s\n", a);
			*arg_var = argv[i++];
			continue;
		}

		USAGE_MSG(argc, argv, "Error: invalid flag %s\n", a);
	}
	if (op < 0)
		USAGE_MSG(argc, argv, "Error: -encode|-decode required\n");

	// Load input
	size_t file_size = 0; // allocated in IN
	size_t in_size = PAGE_SIZE;      // used in IN
	void *in_buff = NULL;         // input buffer
	int in_fd = -1;          // input file desc
	size_t file_size;

	if (in_file != 0) {
		// If we have a file name, open it, and allocate the exact input size
		struct stat st;
		in_fd = open(in_file, O_RDONLY);
		if (in_fd < 0) {
			perror(in_file);
			exit(1);
		}
		if (fstat(in_fd, &st) != 0) {
			perror(in_file);
			exit(1);
		}
		if (st.st_size > SIZE_MAX) {
			fprintf(stderr, "File is too large\n");
			exit(1);
		}
		file_size = PAGE_SIZE;
	} else {
		in_fd = 0;
	}

	size_t out_allocated = (op == LZFSE_ENCODE) ? PAGE_SIZE : (4 * PAGE_SIZE);
}
