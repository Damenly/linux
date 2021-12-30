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

#ifndef LZFSE_H
#define LZFSE_H

#include <linux/stddef.h>
#include <linux/types.h>

#include "lzvn.h"
/*! @abstract Get the required scratch buffer size to compress using LZFSE.   */
size_t lzfse_encode_scratch_size(void);

/*! @abstract Compress a buffer using LZFSE.
 *
 *  @param dst_buffer
 *  Pointer to the first byte of the destination buffer.
 *
 *  @param dst_size
 *  Size of the destination buffer in bytes.
 *
 *  @param src_buffer
 *  Pointer to the first byte of the source buffer.
 *
 *  @param src_size
 *  Size of the source buffer in bytes.
 *
 *  @param scratch_buffer
 *  If non-NULL, a pointer to scratch space for the routine to use as workspace;
 *  the routine may use up to lzfse_encode_scratch_size( ) bytes of workspace
 *  during its operation, and will not perform any internal allocations. If
 *  NULL, the routine may allocate its own memory to use during operation via
 *  a single call to malloc( ), and will release it by calling free( ) prior
 *  to returning. For most use, passing NULL is perfectly satisfactory, but if
 *  you require strict control over allocation, you will want to pass an
 *  explicit scratch buffer.
 *
 *  @return
 *  The number of bytes written to the destination buffer if the input is
 *  successfully compressed. If the input cannot be compressed to fit into
 *  the provided buffer, or an error occurs, zero is returned, and the
 *  contents of dst_buffer are unspecified.                                   */
size_t lzfse_encode_buffer(uint8_t *dst_buffer,
                                     size_t dst_size,
                                     const uint8_t *src_buffer,
                                     size_t src_size,
                                     void *scratch_buffer);

/*! @abstract Get the required scratch buffer size to decompress using LZFSE. */
size_t lzfse_decode_scratch_size(void);

/*! @abstract Decompress a buffer using LZFSE.
 *
 *  @param dst_buffer
 *  Pointer to the first byte of the destination buffer.
 *
 *  @param dst_size
 *  Size of the destination buffer in bytes.
 *
 *  @param src_buffer
 *  Pointer to the first byte of the source buffer.
 *
 *  @param src_size
 *  Size of the source buffer in bytes.
 *
 *  @param scratch_buffer
 *  If non-NULL, a pointer to scratch space for the routine to use as workspace;
 *  the routine may use up to lzfse_decode_scratch_size( ) bytes of workspace
 *  during its operation, and will not perform any internal allocations. If
 *  NULL, the routine may allocate its own memory to use during operation via
 *  a single call to malloc( ), and will release it by calling free( ) prior
 *  to returning. For most use, passing NULL is perfectly satisfactory, but if
 *  you require strict control over allocation, you will want to pass an
 *  explicit scratch buffer.
 *
 *  @return
 *  The number of bytes written to the destination buffer if the input is
 *  successfully decompressed. If there is not enough space in the destination
 *  buffer to hold the entire expanded output, only the first dst_size bytes
 *  will be written to the buffer and dst_size is returned. Note that this
 *  behavior differs from that of lzfse_encode_buffer.                        */
size_t lzfse_decode_buffer(uint8_t *dst_buffer,
                                     size_t dst_size,
                                     const uint8_t *src_buffer,
                                     size_t src_size,
                                     void *scratch_buffer);


//  Throughout LZFSE we refer to "L", "M" and "D"; these will always appear as
//  a triplet, and represent a "usual" LZ-style literal and match pair.  "L"
//  is the number of literal bytes, "M" is the number of match bytes, and "D"
//  is the match "distance"; the distance in bytes between the current pointer
//  and the start of the match.
#define LZFSE_ENCODE_HASH_VALUES (1 << LZFSE_ENCODE_HASH_BITS)
#define LZFSE_ENCODE_L_SYMBOLS 20
#define LZFSE_ENCODE_M_SYMBOLS 20
#define LZFSE_ENCODE_D_SYMBOLS 64
#define LZFSE_ENCODE_LITERAL_SYMBOLS 256
#define LZFSE_ENCODE_L_STATES 64
#define LZFSE_ENCODE_M_STATES 64
#define LZFSE_ENCODE_D_STATES 256
#define LZFSE_ENCODE_LITERAL_STATES 1024
#define LZFSE_MATCHES_PER_BLOCK 10000
#define LZFSE_LITERALS_PER_BLOCK (4 * LZFSE_MATCHES_PER_BLOCK)
#define LZFSE_DECODE_LITERALS_PER_BLOCK (4 * LZFSE_DECODE_MATCHES_PER_BLOCK)

//  LZFSE internal status. These values are used by internal LZFSE routines
//  as return codes.  There should not be any good reason to change their
//  values; it is plausible that additional codes might be added in the
//  future.
#define LZFSE_STATUS_OK 0
#define LZFSE_STATUS_SRC_EMPTY -1
#define LZFSE_STATUS_DST_FULL -2
#define LZFSE_STATUS_ERROR -3


//  Select between 32/64-bit I/O streams for FSE. Note that the FSE stream
//  size need not match the word size of the machine, but in practice you
//  want to use 64b streams on 64b systems for better performance.
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
#define FSE_IOSTREAM_64 1
#else
#define FSE_IOSTREAM_64 0
#endif

// MARK: - Bit utils

/*! @abstract Signed type used to represent bit count. */
typedef int32_t fse_bit_count;

/*! @abstract Unsigned type used to represent FSE state. */
typedef uint16_t fse_state;



// MARK: - Bit stream

// I/O streams
// The streams can be shared between several FSE encoders/decoders, which is why
// they are not in the state struct

/*! @abstract Output stream, 64-bit accum. */
typedef struct {
  uint64_t accum;            // Output bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_out_stream64;

/*! @abstract Output stream, 32-bit accum. */
typedef struct {
  uint32_t accum;            // Output bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_out_stream32;

/*! @abstract Object representing an input stream. */
typedef struct {
  uint64_t accum;            // Input bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_in_stream64;

/*! @abstract Object representing an input stream. */
typedef struct {
  uint32_t accum;            // Input bits
  fse_bit_count accum_nbits; // Number of valid bits in ACCUM, other bits are 0
} fse_in_stream32;


// MARK: - Encode/Decode

// Map to 32/64-bit implementations and types for I/O
#if FSE_IOSTREAM_64

typedef uint64_t fse_bits;
typedef fse_out_stream64 fse_out_stream;
typedef fse_in_stream64 fse_in_stream;
#define fse_mask_lsb fse_mask_lsb64
#define fse_extract_bits fse_extract_bits64
#define fse_out_init fse_out_init64
#define fse_out_flush fse_out_flush64
#define fse_out_finish fse_out_finish64
#define fse_out_push fse_out_push64
#define fse_in_init fse_in_checked_init64
#define fse_in_checked_init fse_in_checked_init64
#define fse_in_flush fse_in_checked_flush64
#define fse_in_checked_flush fse_in_checked_flush64
#define fse_in_flush2(_unused, _parameters, _unused2) 0 /* nothing */
#define fse_in_checked_flush2(_unused, _parameters)     /* nothing */
#define fse_in_pull fse_in_pull64

#else

typedef uint32_t fse_bits;
typedef fse_out_stream32 fse_out_stream;
typedef fse_in_stream32 fse_in_stream;
#define fse_mask_lsb fse_mask_lsb32
#define fse_extract_bits fse_extract_bits32
#define fse_out_init fse_out_init32
#define fse_out_flush fse_out_flush32
#define fse_out_finish fse_out_finish32
#define fse_out_push fse_out_push32
#define fse_in_init fse_in_checked_init32
#define fse_in_checked_init fse_in_checked_init32
#define fse_in_flush fse_in_checked_flush32
#define fse_in_checked_flush fse_in_checked_flush32
#define fse_in_flush2 fse_in_checked_flush32
#define fse_in_checked_flush2 fse_in_checked_flush32
#define fse_in_pull fse_in_pull32

#endif

//  Type representing an offset between elements in a buffer. On 64-bit
//  systems, this is stored in a 64-bit container to avoid extra sign-
//  extension operations in addressing arithmetic, but the value is always
//  representable as a 32-bit signed value in LZFSE's usage.
#if defined(_M_AMD64) || defined(__x86_64__) || defined(__arm64__)
typedef int64_t lzfse_offset;
#else
typedef int32_t lzfse_offset;
#endif


//  Parameters controlling details of the LZ-style match search. These values
//  may be modified to fine tune compression ratio vs. encoding speed, while
//  keeping the compressed format compatible with LZFSE. Note that
//  modifying them will also change the amount of work space required by
//  the encoder. The values here are those used in the compression library
//  on iOS and OS X.

//  Number of bits for hash function to produce. Should be in the range
//  [10, 16]. Larger values reduce the number of false-positive found during
//  the match search, and expand the history table, which may allow additional
//  matches to be found, generally improving the achieved compression ratio.
//  Larger values also increase the workspace size, and make it less likely
//  that the history table will be present in cache, which reduces performance.
#define LZFSE_ENCODE_HASH_BITS 14

//  Number of positions to store for each line in the history table. May
//  be either 4 or 8. Using 8 doubles the size of the history table, which
//  increases the chance of finding matches (thus improving compression ratio),
//  but also increases the workspace size.
#define LZFSE_ENCODE_HASH_WIDTH 4

//  Match length in bytes to cause immediate emission. Generally speaking,
//  LZFSE maintains multiple candidate matches and waits to decide which match
//  to emit until more information is available. When a match exceeds this
//  threshold, it is emitted immediately. Thus, smaller values may give
//  somewhat better performance, and larger values may give somewhat better
//  compression ratios.
#define LZFSE_ENCODE_GOOD_MATCH 40

//  When the source buffer is very small, LZFSE doesn't compress as well as
//  some simpler algorithms. To maintain reasonable compression for these
//  cases, we transition to use LZVN instead if the size of the source buffer
//  is below this threshold.
#define LZFSE_ENCODE_LZVN_THRESHOLD 4096


/*! @abstract History table set. Each line of the history table represents a set
 *  of candidate match locations, each of which begins with four bytes with the
 *  same hash. The table contains not only the positions, but also the first
 *  four bytes at each position. This doubles the memory footprint of the
 *  table, but allows us to quickly eliminate false-positive matches without
 *  doing any pointer chasing and without pulling in any additional cachelines.
 *  This provides a large performance win in practice. */
typedef struct {
  int32_t pos[LZFSE_ENCODE_HASH_WIDTH];
  uint32_t value[LZFSE_ENCODE_HASH_WIDTH];
} lzfse_history_set;

/*! @abstract An lzfse match is a sequence of bytes in the source buffer that
 *  exactly matches an earlier (but possibly overlapping) sequence of bytes in
 *  the same buffer.
 *  @code
 *  exeMPLARYexaMPLE
 *  |  |     | ||-|--- lzfse_match2.length=3
 *  |  |     | ||----- lzfse_match2.pos
 *  |  |     |-|------ lzfse_match1.length=3
 *  |  |     |-------- lzfse_match1.pos
 *  |  |-------------- lzfse_match2.ref
 *  |----------------- lzfse_match1.ref
 *  @endcode
 */
typedef struct {
  //  Offset of the first byte in the match.
  lzfse_offset pos;
  //  First byte of the source -- the earlier location in the buffer with the
  //  same contents.
  lzfse_offset ref;
  //  Length of the match.
  uint32_t length;
} lzfse_match;

// MARK: - Encoder and Decoder state objects

/*! @abstract Encoder state object. */
typedef struct {
  //  Pointer to first byte of the source buffer.
  const uint8_t *src;
  //  Length of the source buffer in bytes. Note that this is not a size_t,
  //  but rather lzfse_offset, which is a signed type. The largest
  //  representable buffer is 2GB, but arbitrarily large buffers may be
  //  handled by repeatedly calling the encoder function and "translating"
  //  the state between calls. When doing this, it is beneficial to use
  //  blocks smaller than 2GB in order to maintain residency in the last-level
  //  cache. Consult the implementation of lzfse_encode_buffer for details.
  lzfse_offset src_end;
  //  Offset of the first byte of the next literal to encode in the source
  //  buffer.
  lzfse_offset src_literal;
  //  Offset of the byte currently being checked for a match.
  lzfse_offset src_encode_i;
  //  The last byte offset to consider for a match.  In some uses it makes
  //  sense to use a smaller offset than src_end.
  lzfse_offset src_encode_end;
  //  Pointer to the next byte to be written in the destination buffer.
  uint8_t *dst;
  //  Pointer to the first byte of the destination buffer.
  uint8_t *dst_begin;
  //  Pointer to one byte past the end of the destination buffer.
  uint8_t *dst_end;
  //  Pending match; will be emitted unless a better match is found.
  lzfse_match pending;
  //  The number of matches written so far. Note that there is no problem in
  //  using a 32-bit field for this quantity, because the state already limits
  //  us to at most 2GB of data; there cannot possibly be more matches than
  //  there are bytes in the input.
  uint32_t n_matches;
  //  The number of literals written so far.
  uint32_t n_literals;
  //  Lengths of found literals.
  uint32_t l_values[LZFSE_MATCHES_PER_BLOCK];
  //  Lengths of found matches.
  uint32_t m_values[LZFSE_MATCHES_PER_BLOCK];
  //  Distances of found matches.
  uint32_t d_values[LZFSE_MATCHES_PER_BLOCK];
  //  Concatenated literal bytes.
  uint8_t literals[LZFSE_LITERALS_PER_BLOCK];
  //  History table used to search for matches. Each entry of the table
  //  corresponds to a group of four byte sequences in the input stream
  //  that hash to the same value.
  lzfse_history_set history_table[LZFSE_ENCODE_HASH_VALUES];
} lzfse_encoder_state;

/*! @abstract  Entry for one state in the value decoder table (64b). */
typedef struct {      // DO NOT REORDER THE FIELDS
  uint8_t total_bits; // state bits + extra value bits = shift for next decode
  uint8_t value_bits; // extra value bits
  int16_t delta;      // state base (delta)
  int32_t vbase;      // value base
} fse_value_decoder_entry;


/*! @abstract Decoder state object for lzfse compressed blocks. */
typedef struct {
  //  Number of matches remaining in the block.
  uint32_t n_matches;
  //  Number of bytes used to encode L, M, D triplets for the block.
  uint32_t n_lmd_payload_bytes;
  //  Pointer to the next literal to emit.
  const uint8_t *current_literal;
  //  L, M, D triplet for the match currently being emitted. This is used only
  //  if we need to restart after reaching the end of the destination buffer in
  //  the middle of a literal or match.
  int32_t l_value, m_value, d_value;
  //  FSE stream object.
  fse_in_stream lmd_in_stream;
  //  Offset of L,M,D encoding in the input buffer. Because we read through an
  //  FSE stream *backwards* while decoding, this is decremented as we move
  //  through a block.
  uint32_t lmd_in_buf;
  //  The current state of the L, M, and D FSE decoders.
  uint16_t l_state, m_state, d_state;
  //  Internal FSE decoder tables for the current block. These have
  //  alignment forced to 8 bytes to guarantee that a single state's
  //  entry cannot span two cachelines.
  fse_value_decoder_entry l_decoder[LZFSE_ENCODE_L_STATES] __attribute__((__aligned__(8)));
  fse_value_decoder_entry m_decoder[LZFSE_ENCODE_M_STATES] __attribute__((__aligned__(8)));
  fse_value_decoder_entry d_decoder[LZFSE_ENCODE_D_STATES] __attribute__((__aligned__(8)));
  int32_t literal_decoder[LZFSE_ENCODE_LITERAL_STATES];
  //  The literal stream for the block, plus padding to allow for faster copy
  //  operations.
  uint8_t literals[LZFSE_LITERALS_PER_BLOCK + 64];
} lzfse_compressed_block_decoder_state;

//  Decoder state object for uncompressed blocks.
typedef struct { uint32_t n_raw_bytes; } uncompressed_block_decoder_state;

/*! @abstract Decoder state object. */
typedef struct {
  //  Pointer to next byte to read from source buffer (this is advanced as we
  //  decode; src_begin describe the buffer and do not change).
  const uint8_t *src;
  //  Pointer to first byte of source buffer.
  const uint8_t *src_begin;
  //  Pointer to one byte past the end of the source buffer.
  const uint8_t *src_end;
  //  Pointer to the next byte to write to destination buffer (this is advanced
  //  as we decode; dst_begin and dst_end describe the buffer and do not change).
  uint8_t *dst;
  //  Pointer to first byte of destination buffer.
  uint8_t *dst_begin;
  //  Pointer to one byte past the end of the destination buffer.
  uint8_t *dst_end;
  //  1 if we have reached the end of the stream, 0 otherwise.
  int end_of_stream;
  //  magic number of the current block if we are within a block,
  //  LZFSE_NO_BLOCK_MAGIC otherwise.
  uint32_t block_magic;
  lzfse_compressed_block_decoder_state compressed_lzfse_block_state;
  lzvn_compressed_block_decoder_state compressed_lzvn_block_state;
  uncompressed_block_decoder_state uncompressed_block_state;
} lzfse_decoder_state;


// MARK: - LZFSE encode/decode interfaces
int lzfse_encode_init(lzfse_encoder_state *s);
int lzfse_encode_translate(lzfse_encoder_state *s, lzfse_offset delta);
int lzfse_encode_base(lzfse_encoder_state *s);
int lzfse_encode_finish(lzfse_encoder_state *s);
int lzfse_decode(lzfse_decoder_state *s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* LZFSE_H */
