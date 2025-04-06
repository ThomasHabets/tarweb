#ifndef __INCLUDE_CAST_H__
#define __INCLUDE_CAST_H__

#include <type_traits>
#include <stdexcept>

template <typename To, typename From>
To safe_int_cast(const From from)
{
    if (std::is_signed_v<From> && std::is_unsigned_v<To> && from < 0) {
        throw std::runtime_error("bad value, casting negative to unsigned");
    }
    const To to = static_cast<To>(from);
    if (std::is_unsigned_v<From> && std::is_signed_v<To> && to < 0) {
        throw std::runtime_error("bad value, unsigned value turned negative");
    }
    if (from != static_cast<From>(to)) {
        throw std::runtime_error(
            "bad value, different value when converted back");
    }
    return to;
}
#endif
