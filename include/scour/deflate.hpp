// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_DEFLATE_HPP
#define SCOUR_DEFLATE_HPP

#include <cstddef>
#include <string_view>

#include "scour/bytes.hpp"

namespace scour {

/// Compresses to a zlib stream (RFC 1950) using LZ77 with lazy matching and
/// fixed Huffman codes.
///
/// The encoder is intentionally small and auditable rather than maximally
/// dense: fixed codes cost roughly 5-10% versus zlib's dynamic trees, and in
/// exchange there is no code-length alphabet to get wrong. Callers that care
/// about the last few percent keep the original stream when the rewrite is not
/// smaller (see `ScrubOptions::recompress`).
Bytes deflate(std::string_view input);

/// Same, without the two byte zlib header and the Adler-32 trailer.
Bytes deflate_raw(std::string_view input);

/// zlib stream: 0x78 0x9C header, DEFLATE body, big-endian Adler-32.
Bytes zlib_compress(std::string_view input);

}  // namespace scour

#endif  // SCOUR_DEFLATE_HPP
