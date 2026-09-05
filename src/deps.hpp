#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include <span>
#include <string_view>
#include <unordered_map>

// the only place in the library that names std:: containers and range adaptors

namespace ac
{
	template <class T>
	using span_t = std::span<T>;

	template <class T>
	using optional_t = std::optional<T>;

	template <class T>
	using vector_t = std::vector<T>;

	using string_view_t = std::string_view;

	template <class K, class V>
	using unordered_map_t = std::unordered_map<K, V>;

	using std::memcpy;
}