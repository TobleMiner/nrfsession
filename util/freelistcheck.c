#include <stdlib.h>
#include <errno.h>
#include <avr/io.h>

#include "freelistcheck.h"

struct freelist_err ferr;

freelist_err check_freelist_integrity()
{
	ferr.err = FERR_OK;
	ferr.val = 0;
	ferr.max_chunk_size = 0;
	struct __freelist* fp = __flp;
	while(fp)
	{
		if(fp > RAMEND || fp < 0)
		{
			ferr.err = FP_OUT_OF_RANGE;
			ferr.val = (long long)fp;
			ferr.chunk = fp;
			return ferr;
		}
		ferr.max_chunk_size = ((fp->sz > ferr.max_chunk_size) ? fp->sz : ferr.max_chunk_size);
		if(fp->sz > (RAMEND - RAMSTART))
		{
			ferr.err = SZ_INVALID;
			ferr.val = (long long)fp->sz;
			ferr.chunk = fp;
//			return ferr;
		}
		fp = fp->nx;
	}
	return ferr;
}

size_t malloc_segment_get_size(void* ptr)
{
	struct __freelist* fp;
	ptr -= sizeof(size_t);
	fp = (struct __freelist *)ptr;
	return fp->sz;
}
