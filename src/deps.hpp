#pragma once
#include <cstddef>
#include <cstdint>

#if defined(ARMCALL_DEPS_HDR)
#	include ARMCALL_DEPS_HDR
#else
#	include <array>
#	include <cstring>
#	include <optional>
#	include <span>
#	include <string_view>
#	include <type_traits>
#	include <unordered_map>

namespace ac
{
	template <class T>
	using span_t = std::span<T>;

	template <class T, size_t S>
	using array_t = std::array<T, S>;

	template <class T>
	using optional_t = std::optional<T>;

	using string_view_t = std::string_view;

	template <class K, class V>
	using unordered_map_t = std::unordered_map<K, V>;

	using std::memcpy;
	using std::is_void_v;
}
#endif
