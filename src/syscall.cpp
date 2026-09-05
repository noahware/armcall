#include "syscall.hpp"
#include "deps.hpp"
#include "svc.hpp"

#include <pe.hpp>
#include <Windows.h>

namespace
{
	ac::unordered_map_t<ac::string_view_t, ac::svc_insn> syscalls;
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
		const auto svc = svc_insn::parse(loc);

		if (!svc)
			continue;

		syscalls[exp.name] = svc.value();
	}
}
