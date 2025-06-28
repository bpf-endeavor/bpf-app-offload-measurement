#include <stdio.h>
#include <stdlib.h>

#include "zipf.h"

#define ENTREIS 100000

static void do_exp_for(double s, FILE *output)
{
	const size_t size = ENTREIS;
	struct zipfgen *z = new_zipfgen(size, s);
	char line[32];
	for (size_t k = 0; k < 1000000LL; k++) {
		int num = z->gen(z);
		int chars = sprintf(line, "%d\n", num);
		fwrite(line, 1, chars, output);
	}
	free_zipfgen(z);
}

static FILE *open_output_file(double s)
{
	char name[32];
	sprintf(name, "zipf_%.1f.txt", s);
	FILE *f = fopen(name, "w");
	if (f == NULL) {
		fprintf(stderr, "failed to open file: %s\n", name);
		exit(EXIT_FAILURE);
	}
	return f;
}

int main(int argc, char *argv[])
{
	double parameters[] = {0, 0.5, 1.0, 1.5, 2};
	const size_t count_params = sizeof(parameters) / sizeof(parameters[0]);
	for (size_t i = 0; i < count_params; i++) {
		double s = parameters[i];
		printf("@ %f\n", s);
		FILE *f = open_output_file(s);
		do_exp_for(s, f);
		fclose(f);
	}
	return 0;
}
