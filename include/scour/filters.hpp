// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_FILTERS_HPP
#define SCOUR_FILTERS_HPP

#include <string>
#include <string_view>
#include <vector>

#include "scour/bytes.hpp"
#include "scour/error.hpp"
#include "scour/object.hpp"

namespace scour {

/// One filter in a /Filter chain, with its resolved /DecodeParms.
struct FilterSpec {
    std::string name;
    Dict params;
};

struct DecodeResult {
    Bytes data;
    bool image = false;        ///< the stream is an encoded image (DCT/JPX/CCITT/JBIG2)
    bool unsupported = false;  ///< an unknown filter was left in place
    bool checksum_failed = false;
};

/// Applies `/Filter` + `/DecodeParms` to encoded stream bytes. Image codecs are
/// not decoded (Scour never needs pixels); the returned data is then the
/// original bytes and `image` is set, which is what the inspector reports as
/// "text inside images cannot be redacted".
DecodeResult decode_stream_data(std::string_view raw, const std::vector<FilterSpec>& filters,
                                Diagnostics& diagnostics, int page = -1);

/// Resolves /Filter and /DecodeParms from a stream dictionary through `source`.
std::vector<FilterSpec> resolve_filters(const Dict& stream_dict, const ObjectSource& source);

/// PNG/TIFF predictor reversal, exposed for tests.
Bytes apply_predictor(const Bytes& data, const Dict& params);

}  // namespace scour

#endif  // SCOUR_FILTERS_HPP
