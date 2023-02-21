#include <stdlib.h>

#include "userspace/log.h"
#include "params.h"


int main(int argc, char *argv[])
{
	if (parse_args(argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	return 0;
}
