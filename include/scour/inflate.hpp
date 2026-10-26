// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_INFLATE_HPP
#define SCOUR_INFLATE_HPP

#include <cstddef>
#include <string_view>

#include "scour/bytes.hpp"

namespace scour {

/// Decompresses a DEFLATE stream. Accepts both the zlib wrapper (RFC 1950,
/// what /FlateDecode always uses) and headerless raw DEFLATE, because a
/// surprising number of scanners and generators emit the latter.
///
/// Throws ScourError("pdf.deflate.corrupt") on malformed input and
/// ScourError("pdf.deflate.too-large") when the expansion limit is exceeded,
/// which is what stops a decompression bomb from eating all memory.
/// If `checksum_ok` is given it reports whether the zlib Adler-32 trailer
/// matched; a mismatch is a corruption signal but never a fatal error.
Bytes inflate(std::string_view input, std::size_t max_output = std::size_t{1} << 30,
              bool* checksum_ok = nullptr);

/// True when the bytes look like a zlib stream (CMF/FLG with a valid check).
bool looks_like_zlib(std::string_view input) noexcept;

/// Adler-32 checksum, required to validate the zlib trailer.
std::uint32_t adler32(std::string_view data) noexcept;

}  // namespace scour

#endif  // SCOUR_INFLATE_HPP
