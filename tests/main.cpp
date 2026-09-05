#include "../src/syscall.hpp"
#include "../src/insn.hpp"
#include <algorithm>
#include <format>
#include <array>

#define LOG(...) std::printf("%s\n", std::format(__VA_ARGS__).c_str())

int main()
{
    ac::init();

    std::array<std::uint8_t, 4> bytes = { 0xc1, 0x00, 0x00, 0xD4 }; // little-endian
    
    const auto insn = ac::insn::svc::parse(bytes);
    const auto new_insn = ac::insn::svc::encode(0x6);

    const auto new_bytes = new_insn.to_bytes();

    if (std::ranges::equal(bytes, new_bytes))
    {
        LOG("bytes are eq");
    }

	LOG("armcall 0x{:X}", insn ? insn->imm() : 0);

	return 0;
}
