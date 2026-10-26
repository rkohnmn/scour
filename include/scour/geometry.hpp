// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_GEOMETRY_HPP
#define SCOUR_GEOMETRY_HPP

#include <algorithm>
#include <cmath>

namespace scour {

/// Axis-aligned rectangle in PDF user space, normalised so x0 <= x1 and
/// y0 <= y1.
struct Rect {
    double x0 = 0.0;
    double y0 = 0.0;
    double x1 = 0.0;
    double y1 = 0.0;

    [[nodiscard]] static Rect from_corners(double ax, double ay, double bx, double by) {
        return Rect{std::min(ax, bx), std::min(ay, by), std::max(ax, bx), std::max(ay, by)};
    }

    [[nodiscard]] double width() const noexcept { return x1 - x0; }
    [[nodiscard]] double height() const noexcept { return y1 - y0; }
    [[nodiscard]] bool empty() const noexcept { return width() <= 0.0 || height() <= 0.0; }
    [[nodiscard]] double area() const noexcept { return empty() ? 0.0 : width() * height(); }
    [[nodiscard]] double center_x() const noexcept { return (x0 + x1) * 0.5; }
    [[nodiscard]] double center_y() const noexcept { return (y0 + y1) * 0.5; }

    [[nodiscard]] Rect united(const Rect& other) const {
        if (other.empty()) return *this;
        if (empty()) return other;
        return Rect{std::min(x0, other.x0), std::min(y0, other.y0), std::max(x1, other.x1),
                    std::max(y1, other.y1)};
    }

    [[nodiscard]] Rect expanded(double amount) const {
        return Rect{x0 - amount, y0 - amount, x1 + amount, y1 + amount};
    }

    [[nodiscard]] bool intersects(const Rect& other) const {
        if (empty() || other.empty()) return false;
        return x0 < other.x1 && other.x0 < x1 && y0 < other.y1 && other.y0 < y1;
    }

    [[nodiscard]] bool contains(double x, double y) const {
        return x >= x0 && x <= x1 && y >= y0 && y <= y1;
    }

    [[nodiscard]] bool approximately_equals(const Rect& other, double tolerance = 1e-6) const {
        return std::fabs(x0 - other.x0) < tolerance && std::fabs(y0 - other.y0) < tolerance &&
               std::fabs(x1 - other.x1) < tolerance && std::fabs(y1 - other.y1) < tolerance;
    }
};

}  // namespace scour

#endif  // SCOUR_GEOMETRY_HPP
