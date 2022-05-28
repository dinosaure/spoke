/*
 * Copyright (c) 2014-2016 David Kaloper Meršinjak
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

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <caml/memory.h>

static inline void xor_into (uint8_t *src, uint8_t *dst, size_t n) {
/* see issue mirage/mirage-crypto#70 mirage/mirage-crypto#81 for alignment
 * considerations (memcpy used below) */
#ifdef ARCH_SIXTYFOUR
  uint64_t s;
  for (; n >= 8; n -= 8, src += 8, dst += 8)
    *(uint64_t*) dst ^= *(uint64_t*)memcpy(&s, src, 8);
#endif

  uint32_t t;
  for (; n >= 4; n -= 4, src += 4, dst += 4)
    *(uint32_t*) dst ^= *(uint32_t*)memcpy(&t, src, 4);

  for (; n --; ++ src, ++ dst) *dst = *src ^ *dst;
}

#define String_off(str, off) ((uint8_t*) String_val (str) + Long_val (off))

CAMLprim value
spoke_xor_into_generic (value src, value src_off, value dst, value dst_off, value len) {
  xor_into (String_off (src, src_off), String_off (dst, dst_off), Long_val (len));
  return Val_unit;
}
