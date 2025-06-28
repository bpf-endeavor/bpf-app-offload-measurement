#include <stdlib.h>
#include <math.h>
#include "zipf.h"

struct zipfgen *new_zipfgen(int n, double s)
{
	int i;
	double h = 0;
	struct zipfgen *ptr = malloc(sizeof(struct zipfgen));
	double *c_probs = malloc((n + 1) * sizeof(double));
	int *c_probs_int = malloc((n+1) *sizeof(int));

	for (i = 1; i < n + 1; i++)
		h += 1.0 / pow((double)i, s);

	c_probs[0] = 0;
	c_probs_int[0] = 0;
	for (i = 1; i < n + 1; i++) {
		c_probs[i] = c_probs[i - 1] + (1.0 / (pow(i, s) * h));
		/* Casting to an integer so at runtime we are not doing
		 * floating points */
		c_probs_int[i] = (int)(c_probs[i] * RAND_MAX);
	}
	free(c_probs);

	/* ptr->c_probs = c_probs; */
	ptr->c_probs = c_probs_int;
	ptr->h = h;
	ptr->s = s;
	ptr->n = n;
	ptr->gen = number_from_zipf_distribution;
	return ptr;
}

void free_zipfgen(struct zipfgen *ptr)
{
	free(ptr->c_probs);
	free(ptr);
}


int myrand(void) {
	const unsigned long a = 1664525;  // Multiplier
	const unsigned long c = 1013904223; // Increment
	const unsigned long m = 4294967296; // 2^32 modulus, typically used for 32-bit integers
	static unsigned long seed = 1;       // Initial seed value
	seed = (a * seed + c) % m;
	return seed % RAND_MAX;
}

/*
 * returns a value in range [1, n]
 * if failed (it should not) it returns -1
 * */
int number_from_zipf_distribution(struct zipfgen *ptr)
{
	int low, high, mid;
	int rnd;

	low = 1;
	high = ptr->n;
	mid = (low + high) / 2;
	__builtin_prefetch(&ptr->c_probs[mid]);
	// get a uniform random number
	/* rnd = ((double)random() / (double)RAND_MAX); */
	/* rnd = rand(); */
	rnd = myrand();

	while (low <= high) {
		mid = (low + high) / 2;
		int is_more = ptr->c_probs[mid] < rnd;
		if (is_more) {
			low = mid + 1;
			continue;
		}
		int is_less = rnd <= ptr->c_probs[mid -1];
		if (is_less) {
			high = mid - 1;
			continue;
		}
		return mid;
	}
	// failed
	return -1;
}
