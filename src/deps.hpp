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
#	include <string>
#	include <string_view>
#	include <type_traits>
#	include <unordered_map>
#	include <vector>
#   include <atomic>
#   include <mutex>

namespace ac
{
	template <class T>
	using vector_t = std::vector<T>;

	template <class T>
	using span_t = std::span<T>;

	template <class T, size_t S>
	using array_t = std::array<T, S>;

	template <class T>
	using optional_t = std::optional<T>;

	using string_view_t = std::string_view;

	template <class T>
	using hash_t = std::hash<T>;

	template <class T>
	using atomic_t = std::atomic<T>;

	using mutex_t = std::mutex;

	template <class T>
	using scoped_lock_t = std::scoped_lock<T>;

	template <class K, class V>
	using unordered_map_t = std::unordered_map<K, V>;

	using std::memory_order_acquire;
	using std::memory_order_release;
	using std::memory_order_relaxed;

	using std::memcpy;
	using std::is_void_v;
}
#endif
