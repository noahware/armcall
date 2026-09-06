#include "../src/syscall.hpp"
#include <Windows.h>
#include <format>
#include <cstdio>

#define LOG(...) std::printf("%s\n", std::format(__VA_ARGS__).c_str())

static void test_time()
{
    LARGE_INTEGER time = { };
    AC_SYSCALL(ZwQuerySystemTime, &time);

    LOG("time: 0x{:X}", time.QuadPart);
}

static void test_mem()
{
    const auto curr_proc = reinterpret_cast<HANDLE>(-1);

    std::uint8_t* base_addr = nullptr;
    std::size_t size = sizeof(std::uint64_t);

    NTSTATUS status = AC_SYSCALL(NtAllocateVirtualMemory, curr_proc, &base_addr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    LOG("allocation base: 0x{:X}, status 0x{:X}", reinterpret_cast<std::uintptr_t>(base_addr), status);

    *base_addr = 0;

    constexpr std::uint8_t expected = 0x13;

    status = AC_SYSCALL(NtWriteVirtualMemory, curr_proc, base_addr, &expected, sizeof(expected), &size);

    LOG("write status 0x{:X}", status);

    if (*base_addr == expected)
    {
        LOG("write happened successfully, byte matches");
    }
    else
    {
        LOG("write did not succeed, bytes do not match");
    }

    size = 0;

    AC_SYSCALL(NtFreeVirtualMemory, curr_proc, &base_addr, &size, MEM_RELEASE);
}

int main()
{
    AC_INIT();

    test_time();
    test_mem();

	return 0;
}
