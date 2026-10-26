// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_VERSION_HPP
#define SCOUR_VERSION_HPP

#include <string_view>

namespace scour {

inline constexpr std::string_view kVersion = "1.0.0";
inline constexpr std::string_view kBuildDate = __DATE__;

}  // namespace scour

#endif  // SCOUR_VERSION_HPP
