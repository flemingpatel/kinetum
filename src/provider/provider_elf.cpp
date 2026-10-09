// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file provider_elf.cpp
 * @brief Exact ELF contract inspection for provider artifacts.
 * @author Fleming Patel
 */

#include "src/provider/provider_elf.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include "src/common/status.hpp"
#include "src/provider/provider_component_abi.h"

namespace kinetum::provider
{
namespace
{

using common::status;
using common::status_code;
using common::status_or;

/** @brief Unique independent file description used by one libelf session. */
class unique_descriptor {
    public:
	/**
	 * @brief Adopt one descriptor.
	 * @param descriptor Sole descriptor transferred into the guard, or -1 for an empty guard.
	 */
	explicit unique_descriptor(int descriptor) noexcept
		: descriptor_(descriptor)
	{
	}

	/** @brief Close the descriptor. */
	~unique_descriptor()
	{
		if (descriptor_ >= 0) {
			(void)::close(descriptor_);
		}
	}

	/** @brief Disable file-description aliasing. */
	unique_descriptor(const unique_descriptor &) = delete;

	/** @brief Disable file-description aliasing by assignment. */
	unique_descriptor &operator=(const unique_descriptor &) = delete;

	/** @return Borrowed descriptor, or -1 for an empty guard. */
	[[nodiscard]] int get() const noexcept
	{
		return descriptor_;
	}

    private:
	int descriptor_{-1};  ///< Unique descriptor.
};

/** @brief Unique libelf session. */
class unique_elf {
    public:
	/**
	 * @brief Adopt one libelf handle.
	 * @param elf Sole libelf session transferred into the guard, or nullptr.
	 */
	explicit unique_elf(Elf *elf) noexcept
		: elf_(elf)
	{
	}

	/** @brief End the libelf session. */
	~unique_elf()
	{
		if (elf_ != nullptr) {
			(void)::elf_end(elf_);
		}
	}

	/** @brief Disable libelf-handle aliasing. */
	unique_elf(const unique_elf &) = delete;

	/** @brief Disable libelf-handle aliasing by assignment. */
	unique_elf &operator=(const unique_elf &) = delete;

	/** @return Borrowed libelf session, or nullptr for an empty guard. */
	[[nodiscard]] Elf *get() const noexcept
	{
		return elf_;
	}

    private:
	Elf *elf_{nullptr};  ///< Unique libelf handle.
};

/** Exact parsed ELF details needed for role-specific checks. */
struct parsed_elf {
	/** One externally reachable defined dynamic symbol. */
	struct public_definition {
		std::string name;	      ///< Exact dynamic-symbol name.
		unsigned char binding{0};     ///< ELF symbol binding.
		unsigned char visibility{0};  ///< ELF symbol visibility.
		unsigned char type{0};	      ///< ELF symbol type.
	};

	provider_elf_facts facts;			    ///< SONAME and direct dependency set.
	std::vector<public_definition> public_definitions;  ///< Externally reachable definitions.
	bool bind_now{false};				    ///< Immediate relocation is encoded.
	bool relro{false};				    ///< PT_GNU_RELRO is present.
	bool non_executable_stack{false};		    ///< PT_GNU_STACK exists without PF_X.
	bool text_relocation{false};			    ///< DT_TEXTREL is present.
	bool loader_search_path{false};			    ///< DT_RPATH or DT_RUNPATH is present.
	bool disallowed_dynamic_behavior{false};	    ///< Loader behavior exceeds exact local policy.
	bool gnu_unique_definition{false};		    ///< Defined STB_GNU_UNIQUE symbol is present.
	bool symbol_version_definitions{false};		    ///< DT_VERDEF/DT_VERDEFNUM is present.
};

/**
 * @brief Return one supported target tuple's exact ELF machine.
 *
 * @param target Exact release target tuple.
 * @return EM_AARCH64 or EM_X86_64 for the supported target tuple.
 */
uint16_t target_elf_machine(provider_target_tuple target) noexcept
{
	switch (target) {
	case provider_target_tuple::LINUX_GNU_AARCH64:
		return EM_AARCH64;
	case provider_target_tuple::LINUX_GNU_X86_64:
		return EM_X86_64;
	}
	std::abort();
}

/**
 * @brief Build a libelf failure status.
 *
 * @param action Stable failed operation.
 * @return INTERNAL_ERROR carrying libelf's current diagnostic.
 */
status elf_failure(std::string action)
{
	const char *detail = ::elf_errmsg(-1);
	return status(status_code::INTERNAL_ERROR, std::move(action),
		      detail != nullptr ? std::string(detail) : "unknown libelf failure");
}

/**
 * @brief Parse direct dynamic tags and dependencies.
 *
 * @param elf Open libelf handle.
 * @param section Dynamic section.
 * @param header Dynamic section header.
 * @param parsed Non-null destination.
 * @return OK or the first malformed-section error.
 */
status parse_dynamic_section(Elf *elf, Elf_Scn *section, const GElf_Shdr &header, parsed_elf *parsed)
{
	Elf_Data *data = ::elf_getdata(section, nullptr);
	if (data == nullptr) {
		return elf_failure("provider ELF dynamic section is unreadable");
	}
	if (header.sh_entsize == 0 || (header.sh_size % header.sh_entsize) != 0) {
		return status::invalid_argument("provider ELF dynamic section has an invalid entry shape");
	}
	const std::size_t count = static_cast<std::size_t>(header.sh_size / header.sh_entsize);
	if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
		return status::resource_exhausted("provider ELF dynamic-entry count exceeds libelf's index range");
	}
	for (std::size_t index = 0; index < count; ++index) {
		GElf_Dyn entry{};
		if (::gelf_getdyn(data, static_cast<int>(index), &entry) == nullptr) {
			return elf_failure("provider ELF dynamic entry is unreadable");
		}
		switch (entry.d_tag) {
		case DT_NEEDED: {
			const char *name =
				::elf_strptr(elf, header.sh_link, static_cast<std::size_t>(entry.d_un.d_val));
			if (name == nullptr || *name == '\0') {
				return status::invalid_argument("provider ELF contains an invalid DT_NEEDED name");
			}
			parsed->facts.needed_sonames.emplace_back(name);
			break;
		}
		case DT_SONAME: {
			const char *name =
				::elf_strptr(elf, header.sh_link, static_cast<std::size_t>(entry.d_un.d_val));
			if (name == nullptr || *name == '\0' || !parsed->facts.soname.empty()) {
				return status::invalid_argument(
					"provider ELF contains an invalid or duplicate DT_SONAME");
			}
			parsed->facts.soname = name;
			break;
		}
		case DT_BIND_NOW:
			parsed->bind_now = true;
			break;
		case DT_FLAGS: {
			constexpr GElf_Xword ALLOWED_FLAGS = static_cast<GElf_Xword>(DF_BIND_NOW);
			parsed->bind_now = parsed->bind_now || (entry.d_un.d_val & DF_BIND_NOW) != 0;
			parsed->disallowed_dynamic_behavior = parsed->disallowed_dynamic_behavior ||
							      (entry.d_un.d_val & ~ALLOWED_FLAGS) != 0;
			break;
		}
		case DT_FLAGS_1: {
			constexpr GElf_Xword ALLOWED_FLAGS_1 = static_cast<GElf_Xword>(DF_1_NOW);
			parsed->bind_now = parsed->bind_now || (entry.d_un.d_val & DF_1_NOW) != 0;
			parsed->disallowed_dynamic_behavior = parsed->disallowed_dynamic_behavior ||
							      (entry.d_un.d_val & ~ALLOWED_FLAGS_1) != 0;
			break;
		}
		case DT_TEXTREL:
			parsed->text_relocation = true;
			break;
		case DT_RPATH:
		case DT_RUNPATH:
			parsed->loader_search_path = true;
			break;
		case DT_VERDEF:
		case DT_VERDEFNUM:
			parsed->symbol_version_definitions = true;
			break;
		case DT_SYMBOLIC:
#if defined(DT_FILTER)
		case DT_FILTER:
#endif
#if defined(DT_AUXILIARY)
		case DT_AUXILIARY:
#endif
#if defined(DT_AUDIT)
		case DT_AUDIT:
#endif
#if defined(DT_DEPAUDIT)
		case DT_DEPAUDIT:
#endif
#if defined(DT_CONFIG)
		case DT_CONFIG:
#endif
			parsed->disallowed_dynamic_behavior = true;
			break;
#if defined(DT_POSFLAG_1)
		case DT_POSFLAG_1:
			parsed->disallowed_dynamic_behavior = parsed->disallowed_dynamic_behavior ||
							      entry.d_un.d_val != 0;
			break;
#endif
#if defined(DT_FEATURE_1)
		case DT_FEATURE_1:
			parsed->disallowed_dynamic_behavior = parsed->disallowed_dynamic_behavior ||
							      entry.d_un.d_val != 0;
			break;
#endif
		default:
			break;
		}
	}
	std::sort(parsed->facts.needed_sonames.begin(), parsed->facts.needed_sonames.end());
	if (std::adjacent_find(parsed->facts.needed_sonames.begin(), parsed->facts.needed_sonames.end()) !=
	    parsed->facts.needed_sonames.end()) {
		return status::invalid_argument("provider ELF contains duplicate DT_NEEDED identities");
	}
	return status::ok();
}

/**
 * @brief Parse default/protected defined dynamic symbols.
 *
 * @param elf Open libelf handle.
 * @param section Dynamic-symbol section.
 * @param header Dynamic-symbol section header.
 * @param parsed Non-null destination.
 * @return OK or the first malformed-symbol error.
 */
status parse_dynamic_symbols(Elf *elf, Elf_Scn *section, const GElf_Shdr &header, parsed_elf *parsed)
{
	Elf_Data *data = ::elf_getdata(section, nullptr);
	if (data == nullptr) {
		return elf_failure("provider ELF dynamic-symbol section is unreadable");
	}
	if (header.sh_entsize == 0 || (header.sh_size % header.sh_entsize) != 0) {
		return status::invalid_argument("provider ELF dynamic-symbol section has an invalid entry shape");
	}
	const std::size_t count = static_cast<std::size_t>(header.sh_size / header.sh_entsize);
	if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
		return status::resource_exhausted("provider ELF dynamic-symbol count exceeds libelf's index range");
	}
	for (std::size_t index = 0; index < count; ++index) {
		GElf_Sym symbol{};
		if (::gelf_getsym(data, static_cast<int>(index), &symbol) == nullptr) {
			return elf_failure("provider ELF dynamic symbol is unreadable");
		}
		if (symbol.st_shndx == SHN_UNDEF) {
			continue;
		}
		const unsigned char binding = GELF_ST_BIND(symbol.st_info);
		const unsigned char visibility = GELF_ST_VISIBILITY(symbol.st_other);
		if (binding == STB_GNU_UNIQUE) {
			parsed->gnu_unique_definition = true;
		}
		if ((binding != STB_GLOBAL && binding != STB_WEAK) ||
		    (visibility != STV_DEFAULT && visibility != STV_PROTECTED)) {
			continue;
		}
		const char *name = ::elf_strptr(elf, header.sh_link, symbol.st_name);
		if (name == nullptr || *name == '\0') {
			return status::invalid_argument("provider ELF contains an unnamed public definition");
		}
		parsed->public_definitions.push_back(parsed_elf::public_definition{
			name, binding, visibility, static_cast<unsigned char>(GELF_ST_TYPE(symbol.st_info))});
	}
	std::sort(parsed->public_definitions.begin(), parsed->public_definitions.end(),
		  [](const auto &left, const auto &right) { return left.name < right.name; });
	return status::ok();
}

/**
 * @brief Parse and validate common provider ELF structure.
 *
 * @param file Exact held artifact.
 * @param target Exact release target tuple.
 * @return Parsed hardened ELF facts.
 */
status_or<parsed_elf> parse_provider_elf(const common::held_file &file, provider_target_tuple target)
{
	if (!file.valid()) {
		return status::failed_precondition("cannot inspect an empty provider artifact");
	}
	if (::elf_version(EV_CURRENT) == EV_NONE) {
		return elf_failure("libelf rejected its current ABI version");
	}
	const std::string descriptor_path = file.proc_descriptor_path();
	const int independent_descriptor = ::open(descriptor_path.c_str(), O_RDONLY | O_CLOEXEC);
	if (independent_descriptor < 0) {
		return status(status_code::INTERNAL_ERROR, "failed to reopen held provider identity",
			      std::strerror(errno));
	}
	unique_descriptor descriptor(independent_descriptor);
	unique_elf elf(::elf_begin(descriptor.get(), ELF_C_READ, nullptr));
	if (elf.get() == nullptr) {
		return elf_failure("provider artifact is not a readable ELF image");
	}
	if (::elf_kind(elf.get()) != ELF_K_ELF) {
		return status::invalid_argument("provider artifact is not an ELF object");
	}

	GElf_Ehdr executable_header{};
	if (::gelf_getehdr(elf.get(), &executable_header) == nullptr) {
		return elf_failure("provider ELF header is unreadable");
	}
	std::size_t identity_size = 0;
	const char *identity = ::elf_getident(elf.get(), &identity_size);
	if (identity == nullptr || identity_size < EI_NIDENT || identity[EI_CLASS] != ELFCLASS64 ||
	    identity[EI_DATA] != ELFDATA2LSB || executable_header.e_type != ET_DYN ||
	    executable_header.e_machine != target_elf_machine(target)) {
		return status::failed_precondition(
			"provider artifact does not match the exact selected 64-bit ET_DYN target tuple");
	}

	parsed_elf parsed;
	std::size_t program_count = 0;
	if (::elf_getphdrnum(elf.get(), &program_count) != 0) {
		return elf_failure("provider ELF program-header count is unreadable");
	}
	if (program_count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
		return status::resource_exhausted("provider ELF program-header count exceeds libelf's index range");
	}
	bool relro_seen = false;
	bool stack_seen = false;
	for (std::size_t index = 0; index < program_count; ++index) {
		GElf_Phdr header{};
		if (::gelf_getphdr(elf.get(), static_cast<int>(index), &header) == nullptr) {
			return elf_failure("provider ELF program header is unreadable");
		}
		if (header.p_type == PT_GNU_RELRO) {
			if (relro_seen) {
				return status::invalid_argument("provider ELF contains duplicate PT_GNU_RELRO headers");
			}
			relro_seen = true;
			parsed.relro = true;
		} else if (header.p_type == PT_GNU_STACK) {
			if (stack_seen) {
				return status::invalid_argument("provider ELF contains duplicate PT_GNU_STACK headers");
			}
			stack_seen = true;
			parsed.non_executable_stack = (header.p_flags & PF_X) == 0;
		} else if (header.p_type == PT_INTERP) {
			return status::failed_precondition("provider shared object must not contain PT_INTERP");
		}
	}

	bool dynamic_seen = false;
	bool dynsym_seen = false;
	Elf_Scn *section = nullptr;
	while ((section = ::elf_nextscn(elf.get(), section)) != nullptr) {
		GElf_Shdr header{};
		if (::gelf_getshdr(section, &header) == nullptr) {
			return elf_failure("provider ELF section header is unreadable");
		}
		if (header.sh_type == SHT_DYNAMIC) {
			if (dynamic_seen) {
				return status::invalid_argument("provider ELF contains multiple dynamic sections");
			}
			dynamic_seen = true;
			auto dynamic_status = parse_dynamic_section(elf.get(), section, header, &parsed);
			if (!dynamic_status.is_ok()) {
				return dynamic_status;
			}
		} else if (header.sh_type == SHT_DYNSYM) {
			if (dynsym_seen) {
				return status::invalid_argument(
					"provider ELF contains multiple dynamic-symbol sections");
			}
			dynsym_seen = true;
			auto symbol_status = parse_dynamic_symbols(elf.get(), section, header, &parsed);
			if (!symbol_status.is_ok()) {
				return symbol_status;
			}
		}
	}
	if (parsed.disallowed_dynamic_behavior) {
		return status::failed_precondition(
			"provider ELF encodes dynamic-loader behavior outside the exact local policy");
	}
	if (!dynamic_seen || !dynsym_seen || !parsed.bind_now || !parsed.relro || !parsed.non_executable_stack ||
	    parsed.text_relocation || parsed.loader_search_path || parsed.gnu_unique_definition) {
		return status::failed_precondition(
			"provider ELF violates immediate-binding, RELRO, non-executable-stack, textrel, "
			"GNU-unique, or search-path policy");
	}
	return parsed;
}

}  // namespace

status inspect_provider_runtime_elf(const common::held_file &file, provider_target_tuple target)
{
	if (!file.valid()) {
		return status::failed_precondition("cannot inspect an empty provider runtime artifact");
	}
	if (::elf_version(EV_CURRENT) == EV_NONE) {
		return elf_failure("libelf rejected its current ABI version");
	}
	const std::string descriptor_path = file.proc_descriptor_path();
	const int independent_descriptor = ::open(descriptor_path.c_str(), O_RDONLY | O_CLOEXEC);
	if (independent_descriptor < 0) {
		return status(status_code::INTERNAL_ERROR, "failed to reopen held provider runtime identity",
			      std::strerror(errno));
	}
	unique_descriptor descriptor(independent_descriptor);
	unique_elf elf(::elf_begin(descriptor.get(), ELF_C_READ, nullptr));
	if (elf.get() == nullptr) {
		return elf_failure("provider runtime artifact is not a readable ELF image");
	}
	if (::elf_kind(elf.get()) != ELF_K_ELF) {
		return status::invalid_argument("provider runtime artifact is not an ELF object");
	}

	GElf_Ehdr executable_header{};
	if (::gelf_getehdr(elf.get(), &executable_header) == nullptr) {
		return elf_failure("provider runtime ELF header is unreadable");
	}
	std::size_t identity_size = 0;
	const char *identity = ::elf_getident(elf.get(), &identity_size);
	const bool executable_type = executable_header.e_type == ET_EXEC || executable_header.e_type == ET_DYN;
	if (identity == nullptr || identity_size < EI_NIDENT || identity[EI_CLASS] != ELFCLASS64 ||
	    identity[EI_DATA] != ELFDATA2LSB || !executable_type ||
	    executable_header.e_machine != target_elf_machine(target)) {
		return status::failed_precondition(
			"provider runtime does not match the exact selected 64-bit executable target tuple");
	}
	return status::ok();
}

status_or<provider_elf_facts> inspect_provider_component_elf(const common::held_file &file,
							     provider_target_tuple target)
{
	auto parsed_or = parse_provider_elf(file, target);
	if (!parsed_or.is_ok()) {
		return parsed_or.error();
	}
	const bool exact_query = parsed_or->public_definitions.size() == 1 &&
				 parsed_or->public_definitions.front().name ==
					 KINETUM_PROVIDER_COMPONENT_QUERY_SYMBOL &&
				 parsed_or->public_definitions.front().binding == STB_GLOBAL &&
				 parsed_or->public_definitions.front().visibility == STV_DEFAULT &&
				 parsed_or->public_definitions.front().type == STT_FUNC;
	if (!parsed_or->facts.soname.empty() || !exact_query || parsed_or->symbol_version_definitions) {
		return status::failed_precondition(
			"provider component must have no SONAME and define exactly one strong "
			"default-visible unversioned component-query function");
	}
	return std::move(parsed_or).value().facts;
}

status_or<provider_elf_facts> inspect_provider_private_elf(const common::held_file &file,
							   std::string_view expected_soname,
							   provider_target_tuple target)
{
	auto parsed_or = parse_provider_elf(file, target);
	if (!parsed_or.is_ok()) {
		return parsed_or.error();
	}
	if (parsed_or->facts.soname != expected_soname) {
		return status::failed_precondition("private provider artifact DT_SONAME disagrees with inventory");
	}
	return std::move(parsed_or).value().facts;
}

}  // namespace kinetum::provider
