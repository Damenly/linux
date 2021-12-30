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

#ifndef LZVN_H
#define LZVN_H

#include <linux/stddef.h>
#include <linux/types.h>

size_t lzvn_decode_scratch_size(void);
size_t lzvn_encode_scratch_size(void);
size_t lzvn_encode_buffer(void *dst, size_t dst_size,
			  const void *src, size_t src_size,
			  void *work);
size_t lzvn_decode_buffer(void *dst, size_t dst_size,
			  const void *src, size_t src_size,
			  void *work);

// MARK: - LZVN encode/decode interfaces

//  Minimum source buffer size for compression. Smaller buffers will not be
//  compressed; the lzvn encoder will simply return.
#define LZVN_ENCODE_MIN_SRC_SIZE ((size_t)8)

//  Maximum source buffer size for compression. Larger buffers will be
//  compressed partially.
#define LZVN_ENCODE_MAX_SRC_SIZE ((size_t)0xffffffffU)

//  Minimum destination buffer size for compression. No compression will take
//  place if smaller.
#define LZVN_ENCODE_MIN_DST_SIZE ((size_t)8)

/*! @abstract Signed offset in buffers, stored on either 32 or 64 bits. */
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
typedef int64_t lzvn_offset;
#else
typedef int32_t lzvn_offset;
#endif


/*! @abstract Base decoder state. */
typedef struct {

  // Decoder I/O

  // Next byte to read in source buffer
  const unsigned char *src;
  // Next byte after source buffer
  const unsigned char *src_end;

  // Next byte to write in destination buffer (by decoder)
  unsigned char *dst;
  // Valid range for destination buffer is [dst_begin, dst_end - 1]
  unsigned char *dst_begin;
  unsigned char *dst_end;
  // Next byte to read in destination buffer (modified by caller)
  unsigned char *dst_current;

  // Decoder state

  // Partially expanded match, or 0,0,0.
  // In that case, src points to the next literal to copy, or the next op-code
  // if L==0.
  size_t L, M, D;

  // Distance for last emitted match, or 0
  lzvn_offset d_prev;

  // Did we decode end-of-stream?
  int end_of_stream;

} lzvn_decoder_state;

/*! @abstract Decode source to destination.
 *  Updates \p state (src,dst,d_prev). */
void lzvn_decode(lzvn_decoder_state *state);

/*! @abstract Decoder state object for lzvn-compressed blocks. */
typedef struct {
  uint32_t n_raw_bytes;
  uint32_t n_payload_bytes;
  uint32_t d_prev;
} lzvn_compressed_block_decoder_state;


/*! @abstract LZVN compressed block header. */
typedef struct {
  //  Magic number, always LZFSE_COMPRESSEDLZVN_BLOCK_MAGIC.
  uint32_t magic;
  //  Number of decoded (output) bytes.
  uint32_t n_raw_bytes;
  //  Number of encoded (source) bytes.
  uint32_t n_payload_bytes;
} lzvn_compressed_block_header;



// ===============================================================
// Types and Constants

#define LZVN_ENCODE_HASH_BITS                                                  \
  14 // number of bits returned by the hash function [10, 16]
#define LZVN_ENCODE_OFFSETS_PER_HASH                                           \
  4 // stored offsets stack for each hash value, MUST be 4
#define LZVN_ENCODE_HASH_VALUES                                                \
  (1 << LZVN_ENCODE_HASH_BITS) // number of entries in hash table
#define LZVN_ENCODE_MAX_DISTANCE                                               \
  0xffff // max match distance we can represent with LZVN encoding, MUST be
         // 0xFFFF
#define LZVN_ENCODE_MIN_MARGIN                                                 \
  8 // min number of bytes required between current and end during encoding,
    // MUST be >= 8
#define LZVN_ENCODE_MAX_LITERAL_BACKLOG                                        \
  400 // if the number of pending literals exceeds this size, emit a long
      // literal, MUST be >= 271

/*! @abstract Type of table entry. */
typedef struct {
  int32_t indices[4]; // signed indices in source buffer
  uint32_t values[4]; // corresponding 32-bit values
} lzvn_encode_entry_type;

// Work size
#define LZVN_ENCODE_WORK_SIZE                                                  \
  (LZVN_ENCODE_HASH_VALUES * sizeof(lzvn_encode_entry_type))

/*! @abstract Match */
typedef struct {
  lzvn_offset m_begin; // beginning of match, current position
  lzvn_offset m_end; // end of match, this is where the next literal would begin
                     // if we emit the entire match
  lzvn_offset M;     // match length M: m_end - m_begin
  lzvn_offset D;     // match distance D
  lzvn_offset K;     // match gain: M - distance storage (L not included)
} lzvn_match_info;

// ===============================================================
// Internal encoder state

/*! @abstract Base encoder state and I/O. */
typedef struct {

  // Encoder I/O

  // Source buffer
  const unsigned char *src;
  // Valid range in source buffer: we can access src[i] for src_begin <= i <
  // src_end. src_begin may be negative.
  lzvn_offset src_begin;
  lzvn_offset src_end;
  // Next byte to process in source buffer
  lzvn_offset src_current;
  // Next byte after the last byte to process in source buffer. We MUST have:
  // src_current_end + 8 <= src_end.
  lzvn_offset src_current_end;
  // Next byte to encode in source buffer, may be before or after src_current.
  lzvn_offset src_literal;

  // Next byte to write in destination buffer
  unsigned char *dst;
  // Valid range in destination buffer: [dst_begin, dst_end - 1]
  unsigned char *dst_begin;
  unsigned char *dst_end;

  // Encoder state

  // Pending match
  lzvn_match_info pending;

  // Distance for last emitted match, or 0
  lzvn_offset d_prev;

  // Hash table used to find matches. Stores LZVN_ENCODE_OFFSETS_PER_HASH 32-bit
  // signed indices in the source buffer, and the corresponding 4-byte values.
  // The number of entries in the table is LZVN_ENCODE_HASH_VALUES.
  lzvn_encode_entry_type *table;

} lzvn_encoder_state;

/*! @abstract Encode source to destination.
 *  Update \p state.
 *  The call ensures \c src_literal is never left too far behind \c src_current. */
void lzvn_encode(lzvn_encoder_state *state);

#endif // end of LZVN_H
