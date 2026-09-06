# armcall

Direct syscall library for ARM64 Windows. This builds stubs that directly syscall to the Windows kernel. It does such by extracting the immediate operand of the `svc` instruction in every ntdll exported function and dynamically allocating a stub which does `svc #imm; ret;`. This avoids having to call through imported DLLs which could be hooked or monitored. C++ standard library usage is abstracted in deps.hpp so it can be switched out with a custom implementation. The library is header-only and requires at least C++ version 20.

# Building tests

To build the test app, run the following commands:

```
cmake -B build
cmake --build build --config Release
```

# Usage

The `AC_SYSCALL(name, args)` and `AC_SYSCALL_AS(return type, name, args)` can be used to make direct syscalls. By default, `AC_SYSCALL` returns NTSTATUS, use `AC_SYSCALL_AS` if you want to specify another return type.

When specifying the name, *do not* encase it in "" string quotations.

## Time example

```c++
LARGE_INTEGER time = { };
AC_SYSCALL(ZwQuerySystemTime, &time);

LOG("time: 0x{:X}", time.QuadPart);
```

## Memory example

```c++
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
```

# Changing the C++ standard library

See \[deps.hpp](src/deps.hpp), which contains the required features. Create a header that defines the required features in the ac:: namespace and `#define ARMCALL\_DEPS\_HDR <path/to/hdr.hpp>`. The library will use that header instead.

# License

The project uses the Apache-2.0 license.
