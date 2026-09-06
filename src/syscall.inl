#pragma once
#include "insn.hpp"

#include <pe.hpp>
#include <Windows.h>
#include <winternl.h>

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

	struct peb_ldr_data
	{
		BYTE Reserved1[8];
		PVOID Reserved2[1];
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
	};

	struct ldr_data_table_entry
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		PVOID Reserved2[2];
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		BYTE Reserved4[8];
		PVOID Reserved5[3];
		PVOID Reserved6;
		ULONG TimeDateStamp;
	};

	inline unordered_map_t<std::size_t, cached_syscall> syscalls;
	inline volatile LONG init_state = 0;

	[[nodiscard]] inline ldr_data_table_entry* find_ntdll() noexcept
	{
		const PTEB teb = NtCurrentTeb();
		const PPEB peb = teb->ProcessEnvironmentBlock;
		const auto ldr = reinterpret_cast<const peb_ldr_data*>(peb->Ldr);

		const auto app_link = ldr->InLoadOrderModuleList.Flink;
		const auto ntdll_link = app_link->Flink;

		return CONTAINING_RECORD(ntdll_link, ldr_data_table_entry, InLoadOrderLinks);
	}

	inline vector_t<std::uint8_t> read_file(const wchar_t* const path)
	{
		const HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	
		if (handle == INVALID_HANDLE_VALUE)
		{
			return { };
		}

		const DWORD size = GetFileSize(handle, nullptr);

		vector_t<std::uint8_t> buffer(size);

		ReadFile(handle, buffer.data(), size, nullptr, nullptr);

		CloseHandle(handle);

		return buffer;
	}

	inline vector_t<std::uint8_t> pe_raw_to_virt(const pe::image* raw)
	{
		vector_t<std::uint8_t> virt_buf(raw->size());

		ac::memcpy(virt_buf.data(), raw->as(), raw->nt_hdrs()->optional_hdr.size_of_headers);

		for (const auto sec : raw->sections())
		{
			const auto dest = virt_buf.data() + sec.virtual_address;
			const auto src = raw->as() + sec.pointer_to_raw_data;

			ac::memcpy(dest, src, sec.size_of_raw_data);
		}

		return virt_buf;
	}

	inline vector_t<std::uint8_t> read_virt_pe(const wchar_t* const path)
	{
		const auto raw_buf = read_file(path);

		return pe_raw_to_virt(reinterpret_cast<const pe::image*>(raw_buf.data()));
	}

	inline vector_t<std::uint8_t> read_virt_pe(const UNICODE_STRING& path)
	{
		const auto count = path.Length / sizeof(wchar_t);
		wchar_t buf[MAX_PATH];

		ac::memcpy(buf, path.Buffer, count * sizeof(wchar_t));
		buf[count] = L'\0';

		return read_virt_pe(buf);
	}

	inline void populate_syscalls()
	{
		const auto ntdll_entry = find_ntdll();
		const auto ntdll_buf = read_virt_pe(ntdll_entry->FullDllName);

		const auto ntdll = reinterpret_cast<const pe::image*>(ntdll_buf.data());

		for (const auto exp : ntdll->exports())
		{
			if (exp.is_ordinal)
				continue;

			const auto loc = exp.loc.addr<const std::uint8_t*>();
			const auto svc = insn::svc::parse(loc);

			if (!svc)
				continue;

			const std::size_t hash = hash_t<string_view_t>{}(exp.name);

			syscalls[hash] = svc.value();
		}
	}

	inline void ensure_init()
	{
		if (InterlockedCompareExchange(&init_state, 1, 0) == 0)
		{
			populate_syscalls();
			InterlockedExchange(&init_state, 2);
			return;
		}

		while (init_state != 2)
			;
	}
}

inline void* ac::stub_of(const string_view_t syscall)
{
	detail::ensure_init();

	const std::size_t hash = hash_t<string_view_t>{}(syscall);
	const auto it = detail::syscalls.find(hash);

	if (it == detail::syscalls.end())
	{
		return nullptr;
	}

	return it->second.create_or_get_stub();
}
