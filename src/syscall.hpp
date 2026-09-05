#pragma once
#include "deps.hpp"

namespace ac
{
    void init();
    void* stub_of(string_view_t syscall);

    template <class T = void, class... Args>
    T syscall(const string_view_t name, Args... args)
    {
        const void* stub = stub_of(name);

        if (!stub)
        {
            // todo: raise exception
            return {};
        }

        using syscall_fn = T(*)(Args...);
        const auto fn = reinterpret_cast<syscall_fn>(stub);

        return fn(args...);
    }
}
