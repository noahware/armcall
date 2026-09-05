#pragma once
#include "deps.hpp"

namespace ac
{
    struct svc_insn
    {
        constexpr static std::size_t len = 4;
        constexpr static std::uint32_t exp_ll = 0x1;
        constexpr static std::uint32_t exp_opc = 0x0;
        constexpr static std::uint32_t exp_opc2 = 0x0;
        constexpr static std::uint32_t exp_fixed = 0xD4;

        svc_insn() noexcept = default;

        explicit svc_insn(const std::uint32_t imm) noexcept
            :   ll(exp_ll),
	            opc2(exp_opc2),
	            imm16(imm),
	            opc(exp_opc),
	            fixed(exp_fixed) { }

        std::uint32_t ll : 2;   // bits [1:0]  - LL, distinguishes SVC/HVC/SMC
        std::uint32_t opc2 : 3;   // bits [4:2]  - opc2, always 0 for this class
        std::uint32_t imm16 : 16;  // bits [20:5] - the immediate (your 0x148)
        std::uint32_t opc : 3;   // bits [23:21] - 000 = SVC, 001 = HVC, 010 = SMC
        std::uint32_t fixed : 8;   // bits [31:24] - always 0xD4 for exception-gen class

        [[nodiscard]] bool valid() const noexcept
        {
            return fixed == exp_fixed &&
                opc == exp_opc &&
                opc2 == exp_opc2 &&
                ll == exp_ll;
        }

        [[nodiscard]] std::uint32_t imm() const noexcept
        {
            return imm16;
        }

        static svc_insn encode(const std::uint32_t imm) noexcept
        {
            return svc_insn{ imm };
        }

        static optional_t<svc_insn> parse(const std::uint8_t* const bytes) noexcept
        {
            return parse(span_t(bytes, len));
        }

        static optional_t<svc_insn> parse(const span_t<const uint8_t> bytes) noexcept
        {
            svc_insn insn;
            ac::memcpy(&insn, bytes.data(), sizeof(insn));

            if (!insn.valid())
            {
                return { };
            }

            return insn;
        }
    };
}