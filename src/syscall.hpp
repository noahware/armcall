#pragma once
#include "deps.hpp"
#include <Windows.h>

#if defined(_MSVC_TRADITIONAL) && _MSVC_TRADITIONAL
#define AC_SYSCALL(name, ...)        ::ac::syscall(#name, __VA_ARGS__)
#define AC_SYSCALL_AS(T, name, ...)  ::ac::syscall<T>(#name, __VA_ARGS__)
#elif defined(__GNUC__) || defined(__clang__)
#define AC_SYSCALL(name, ...)        ::ac::syscall(#name, ##__VA_ARGS__)
#define AC_SYSCALL_AS(T, name, ...)  ::ac::syscall<T>(#name, ##__VA_ARGS__)
#else
#define AC_SYSCALL(name, ...)        ::ac::syscall(#name __VA_OPT__(,) __VA_ARGS__)
#define AC_SYSCALL_AS(T, name, ...)  ::ac::syscall<T>(#name __VA_OPT__(,) __VA_ARGS__)
#endif

namespace ac
{
    void* stub_of(string_view_t syscall);

    template <class T = NTSTATUS, class... Args>
    T syscall(const string_view_t name, Args... args)
    {
        void* const stub = stub_of(name);

        if (!stub)
        {
            // todo: raise exception
            if constexpr (!is_void_v<T>)
            {
                return T{};
            }
            else
            {
                return;
            }
        }

        using syscall_fn = T(*)(Args...);
        const auto fn = reinterpret_cast<syscall_fn>(stub);

        return fn(args...);
    }
}

#include "syscall.inl"
