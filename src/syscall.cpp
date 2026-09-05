#include "syscall.hpp"
#include "deps.hpp"
#include "insn.hpp"

#include <pe.hpp>
#include <Windows.h>

namespace
{
	ac::unordered_map_t<ac::string_view_t, ac::insn::svc> syscalls;
}

void ac::init()
{
	const auto ntdll = reinterpret_cast<const pe::image*>(GetModuleHandleA("ntdll.dll"));

	for (const auto exp : ntdll->exports())
	{
		if (exp.is_ordinal)
			continue;

		// todo: keep only if in exec section

		const auto loc = exp.loc.addr<const std::uint8_t*>();
		const auto svc = insn::svc::parse(loc);

		if (!svc)
			continue;

		syscalls[exp.name] = svc.value();
	}
}
