#include "../src/syscall.hpp"
#include <Windows.h>
#include <format>
#include <cstdio>

#define LOG(...) std::printf("%s\n", std::format(__VA_ARGS__).c_str())

int main()
{
    AC_INIT();

    LARGE_INTEGER time = { };
    const NTSTATUS status = AC_SYSCALL(ZwQuerySystemTime, &time);

	LOG("armcall status 0x{:X}, time: 0x{:X}", status, time.QuadPart);

	return 0;
}
