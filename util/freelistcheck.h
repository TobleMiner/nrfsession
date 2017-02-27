#include <stdlib.h>
#include <inttypes.h>

#include "../../../../Downloads/avr-libc-2.0.0/libc/stdlib/stdlib_private.h"

enum flerr {
	FERR_OK,
	FP_OUT_OF_RANGE,
	SZ_INVALID
};

typedef struct freelist_err {
        enum flerr err;
        long long val;
	size_t max_chunk_size;
	struct __freelist* chunk;
} freelist_err;


extern struct __freelist* __flp;

