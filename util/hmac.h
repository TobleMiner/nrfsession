#ifndef _HMAC_H_
#define _HMAC_H_

#ifdef TARGET_AVR
	#include "avr/hmac.h"
#else
	#include "x86/hmac.h"
#endif

#endif
