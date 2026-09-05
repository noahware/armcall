#pragma once
#include "deps.hpp"

namespace ac
{
    void init();
    void* stub_of(string_view_t syscall);
}
