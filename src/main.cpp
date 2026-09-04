#include <spdlog/spdlog.h>
#include <span>
#include <pe.hpp>

struct svc_insn
{
    constexpr static std::size_t len = 4;

    std::uint32_t ll : 2;   // bits [1:0]  - LL, distinguishes SVC/HVC/SMC
    std::uint32_t opc2 : 3;   // bits [4:2]  - opc2, always 0 for this class
    std::uint32_t imm16 : 16;  // bits [20:5] - the immediate (your 0x148)
    std::uint32_t opc : 3;   // bits [23:21] - 000 = SVC, 001 = HVC, 010 = SMC
    std::uint32_t fixed : 8;   // bits [31:24] - always 0xD4 for exception-gen class

	[[nodiscard]] bool valid() const noexcept
	{
        return fixed == 0xD4 &&
            opc == 0x0 &&
            opc2 == 0x0 &&
            ll == 0x1;
	}

	[[nodiscard]] std::uint32_t imm() const noexcept
	{
        return imm16;
	}

    static std::optional<svc_insn> parse(const std::span<const uint8_t, len> bytes) noexcept
	{
        svc_insn insn;
        std::memcpy(&insn, bytes.data(), sizeof(insn));

        if (!insn.valid())
        {
            return { };
        }

        return insn;
	}
};

int main()
{
	spdlog::info( "armcall" );
	return 0;
}
