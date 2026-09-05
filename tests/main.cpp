#include "../src/syscall.hpp"
#include "../src/insn.hpp"
#include <Windows.h>
#include <algorithm>
#include <format>
#include <array>

#define LOG(...) std::printf("%s\n", std::format(__VA_ARGS__).c_str())

int main()
{
    ac::init();

    LARGE_INTEGER time = { };
    const auto status = ac::syscall<NTSTATUS>("ZwQuerySystemTime", &time);

	LOG("armcall status 0x{:X}, time: 0x{:X}", status, time.QuadPart);

	return 0;
}
