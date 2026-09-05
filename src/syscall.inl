#pragma once
#include "insn.hpp"

#include <pe.hpp>
#include <Windows.h>

namespace ac::detail
{
	class cached_syscall
	{
	public:
		constexpr static std::size_t stub_size = insn::base::len * 2;

		cached_syscall() noexcept = default;

		cached_syscall(const insn::svc svc) noexcept
			:	svc_(svc) { }

		~cached_syscall()
		{
			if (stub_)
			{
				free_stub();
				stub_ = nullptr;
			}
		}

		[[nodiscard]] void* create_or_get_stub() noexcept
		{
			if (stub_)
			{
				return stub_;
			}

			alloc_stub();
			
			return stub_;
		}

	protected:
		void alloc_stub()
		{
			stub_ = VirtualAlloc(nullptr, stub_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!stub_)
			{
				return;
			}

			const auto ret = insn::ret::encode();
			const auto stub_ret = static_cast<std::uint8_t*>(stub_) + sizeof(svc_);

			ac::memcpy(stub_, &svc_, sizeof(svc_));
			ac::memcpy(stub_ret, &ret, sizeof(ret));

			DWORD old_prot = 0;
			VirtualProtect(stub_, stub_size, PAGE_EXECUTE_READ, &old_prot);
		}

		void free_stub()
		{
			if (!stub_)
			{
				return;
			}

			VirtualFree(stub_, 0, MEM_RELEASE);
		}

		insn::svc svc_ = { };
		void* stub_ = nullptr;
	};

	// inline, not an anonymous namespace: every TU including syscall.hpp must
	// share one map, or init() would populate a different one than stub_of() reads
	inline unordered_map_t<string_view_t, cached_syscall> syscalls;
}

inline void ac::init()
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

		detail::syscalls[exp.name] = svc.value();
	}
}

inline void* ac::stub_of(const string_view_t syscall)
{
	const auto it = detail::syscalls.find(syscall);

	if (it == detail::syscalls.end())
	{
		return nullptr;
	}

	return it->second.create_or_get_stub();
}
