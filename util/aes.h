#ifndef _AES_H_
#define _AES_H_

#ifdef TARGET_AVR
	#include "avr/aes.h"
#else
	#include "x86/aes.h"
#endif

#endif
