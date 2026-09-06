#pragma once
#include "insn.hpp"

#include <pe.hpp>
#include <Windows.h>
#include <winternl.h>

namespace ac::detail
{
	class stub_allocator
	{
	public:
		constexpr static std::size_t stub_size = insn::base::len * 2;
		constexpr static std::size_t page_size = 0x1000;
		constexpr static std::size_t page_mask = page_size - 1;
		constexpr static std::size_t usable_size = page_size - sizeof(void*);

		~stub_allocator()
		{
			if (curr_stub_)
			{
				auto page = curr_stub_ & ~page_mask;

				while (page)
				{
					const auto prev = *reinterpret_cast<std::uintptr_t*>(page + usable_size);
					VirtualFree(reinterpret_cast<void*>(page), 0, MEM_RELEASE);
					page = prev;
				}

				curr_stub_ = 0;
			}
		}

		[[nodiscard]] mutex_t& mutex() noexcept
		{
			return mutex_;
		}

		[[nodiscard]] void* next() noexcept
		{
			if (needs_page())
			{
				allocate_page();
			}

			if (!curr_stub_)
			{
				return nullptr;
			}

			const auto stub = reinterpret_cast<void*>(curr_stub_);

			curr_stub_ += stub_size;

			return stub;
		}

	protected:
		void allocate_page() noexcept
		{
			const auto prev = curr_stub_ & ~page_mask;
			const auto page = reinterpret_cast<std::uintptr_t>(VirtualAlloc(nullptr, page_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

			if (!page)
			{
				return;
			}

			if (prev)
			{
				*reinterpret_cast<std::uintptr_t*>(page + usable_size) = prev;
			}

			curr_stub_ = page;
		}

		[[nodiscard]] bool needs_page() const noexcept
		{
			return curr_stub_ == 0 || usable_size <= page_off();
		}

		[[nodiscard]] std::size_t page_off() const noexcept
		{
			return curr_stub_ & page_mask;
		}

		mutex_t mutex_ = { };
		std::uintptr_t curr_stub_ = 0;
	};

	class cached_syscall
	{
	public:
		static stub_allocator stub_alloc;

		cached_syscall() noexcept = default;

		cached_syscall(const insn::svc svc) noexcept
			:	svc_(svc) { }

		cached_syscall& operator=(cached_syscall&& other) noexcept
		{
			svc_ = other.svc_;
			stub_.store(other.stub_.load(memory_order_relaxed), memory_order_relaxed);
			return *this;
		}

		[[nodiscard]] void* create_or_get_stub() noexcept
		{
			if (stub_.load(memory_order_acquire))
			{
				return stub_.load(memory_order_relaxed);
			}

			const scoped_lock_t lock(stub_alloc.mutex());

			if (stub_.load(memory_order_relaxed))
			{
				return stub_.load(memory_order_relaxed);
			}

			void* new_stub = stub_alloc.next();

			if (!new_stub)
			{
				return nullptr;
			}

			const auto ret = insn::ret::encode();

			ac::memcpy(new_stub, &svc_, sizeof(svc_));
			ac::memcpy(static_cast<std::uint8_t*>(new_stub) + sizeof(svc_), &ret, sizeof(ret));

			stub_.store(new_stub, memory_order_release);

			return new_stub;
		}

	protected:
		insn::svc svc_ = { };
		atomic_t<void*> stub_ = nullptr;
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

	inline stub_allocator cached_syscall::stub_alloc;
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

			const auto loc = exp.loc.template addr<const std::uint8_t*>();
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
