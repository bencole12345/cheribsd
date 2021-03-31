/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 SRI International
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <cheri/cheric.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static ssize_t
_strfcap(char * __restrict buf, size_t maxsize, const char * restrict format,
    uintcap_t cap, bool tag)
{
	char tmp[(sizeof(void *) * 2) + 1];
	const char *percent, *opt_start = NULL;
	size_t size = 0;
	long number;
	bool alt = false;

#define	_OUT(str, len)						\
	do {								\
		if (size < maxsize && (len) <= maxsize - size)		\
			memcpy(buf, (str), (len));			\
		buf += (len);						\
		size += (len);						\
	} while(0)
#define OUT(str)							\
	do {								\
		if (opt_start != NULL) {				\
			_OUT(opt_start, percent - opt_start);		\
			opt_start = NULL;				\
		}							\
		_OUT((str), strlen(str));				\
	} while (0)

	for (; *format; ++format) {
		if (*format != '%') {
			*buf = *format;
			buf++;
			size++;
			continue;
		}

		percent = format;
more_pattern:
		switch (*++format) {
		case '\0':
			--format;
			continue;

		case 'a':
			number = cheri_getaddress(cap);
			break;

		case 'A':
			if (!tag || cheri_getsealed(cap)) {
				OUT("(");
				if (!tag) {
					OUT("invalid");
					if (cheri_getsealed(cap))
						OUT(",");
				}
				switch cheri_gettype(cap) {
				case CHERI_OTYPE_UNSEALED:
					break;
				case CHERI_OTYPE_SENTRY:
					OUT("sentry");
					break;
				default:
					OUT("sealed");
					break;
				}
				OUT(")");
			} else
				opt_start = NULL;
			continue;

		case 'b':
			number = cheri_getbase(cap);
			break;

		case 'C': {
			size_t ret;
			// XXX: flush %? output
			if (cheri_is_null_derived(cap)) {
				alt = true;
				number = cheri_getaddress(cap);
				break;
			}
			ret = _strfcap(buf, maxsize - size,
			    "0x%a [%P,0x%b-0x%t]%? %A", cap, tag);
			buf += ret;
			size += ret;
			continue;
		}

		case 'l':
			number = cheri_getlength(cap);
			break;

		case 'o':
			number = cheri_getoffset(cap);
			break;

		case 'p':
			number = cheri_getperm(cap);
			continue;

		case 'P':
			if (cheri_getperm(cap) & CHERI_PERM_STORE_CAP)
				OUT("W");
			if (cheri_getperm(cap) & CHERI_PERM_LOAD_CAP)
				OUT("R");
			if (cheri_getperm(cap) & CHERI_PERM_EXECUTE)
				OUT("x");
			if (cheri_getperm(cap) & CHERI_PERM_STORE)
				OUT("w");
			if (cheri_getperm(cap) & CHERI_PERM_LOAD)
				OUT("r");
#ifdef CHERI_PERM_EXECUTIVE
			if (cheri_getperm(cap) & CHERI_PERM_EXECUTIVE)
				OUT("E");
#endif
			continue;

		case 't':
			number = cheri_gettop(cap);
			break;

		case 'T':
			tag = true;
			continue;

		case 'x': {
			long *words = (long *)&cap;
			snprintf(tmp, sizeof(tmp), "%016lx%016lx", words[0],
			    words[1]);
			OUT(tmp);
			continue;
		}

		case '?':
			opt_start = format;
			while(*(format + 1) != '\0' && *(format + 1) != '%')
				format++;
			continue;

		case '%':
			OUT("%");
			continue;

		case '#':
			alt = true;
			goto more_pattern;
		}

		/* If we're here, we're rendering a number. */
		// XXX: width, zeros, and decimal support
		if (alt)
			OUT("0x");
		snprintf(tmp, sizeof(tmp), "%lx", number);
		OUT(tmp);
	}

	return (size);
}

ssize_t
strfcap(char * __restrict buf, size_t maxsize, const char * restrict format,
    uintcap_t cap)
{
	return (_strfcap(buf, maxsize, format, cap, cheri_gettag(cap)));
}
