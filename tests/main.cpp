#include "../src/syscall.hpp"
#include "../src/svc.hpp"
#include <algorithm>
#include <format>
#include <array>

#define LOG(...) std::printf("%s\n", std::format(__VA_ARGS__).c_str())

int main()
{
    ac::init();

    std::array<std::uint8_t, 4> bytes = { 0xc1, 0x00, 0x00, 0xD4 }; // little-endian
    
    const auto insn = ac::svc_insn::parse(bytes);
    const auto new_insn = ac::svc_insn::encode(0x6);

    const std::span new_bytes(reinterpret_cast<const std::uint8_t*>(&new_insn), sizeof(new_insn));

    if (std::ranges::equal(bytes, new_bytes))
    {
        LOG("bytes are eq");
    }

	LOG("armcall 0x{:X}", insn ? insn->imm() : 0);

	return 0;
}
