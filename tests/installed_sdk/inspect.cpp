// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file inspect.cpp
 * @brief Independent ELF and unload checks for distributed SDK consumers.
 * @author Fleming Patel
 *
 * Uses installed public headers, system libelf, and the system loader only.
 * It shares no production verifier or source-tree include path. Running this
 * project against an in-tree SDK stage is the fast gate; qualification additionally
 * runs it against the distributed SDK where platform source is unavailable.
 */

#include <kinetum/kinetum_sdk.h>

#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <string_view>

#include <dlfcn.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

namespace
{

/** @brief Retire a read-only libelf session. */
struct elf_deleter {
	/** @brief Free the session before its held descriptor retires.
	 * @param value Live session whose ownership is being released.
	 */
	void operator()(Elf *value) const noexcept
	{
		(void)::elf_end(value);
	}
};

/** @brief Close one read-only ELF descriptor. */
struct descriptor {
	int value;  ///< Exact owned open result.
	/** @brief Close the fixture image after all borrowed ELF views retire. */
	~descriptor()
	{
		if (value >= 0) {
			(void)::close(value);
		}
	}
};

/**
 * @brief Emit a focused failed-gate diagnostic.
 * @param path Fixture image under inspection.
 * @param reason Failure reason; null denotes missing loader diagnostics.
 * @return False after writing the focused test failure.
 */
bool reject(const char *path, const char *reason)
{
	(void)std::fprintf(stderr, "%s: %s\n", path, reason == nullptr ? "no diagnostic was supplied" : reason);
	return false;
}

/**
 * @brief Inspect actual exports, ownership binding, and dependency boundaries.
 * @param path Exact fixture image.
 * @param module Whether the sole registration export is required.
 * @return True only when ELF representation, symbol and dependency checks pass.
 */
bool inspect(const char *path, bool module)
{
	descriptor file{::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
	if (file.value < 0 || ::elf_version(EV_CURRENT) == EV_NONE) {
		return reject(path, "ELF open failed");
	}
	std::unique_ptr<Elf, elf_deleter> elf(::elf_begin(file.value, ELF_C_READ, nullptr));
	if (!elf) {
		return reject(path, "ELF session failed");
	}
	GElf_Ehdr header{};
	if (::gelf_getehdr(elf.get(), &header) == nullptr || header.e_ident[EI_CLASS] != ELFCLASS64 ||
	    header.e_ident[EI_DATA] != ELFDATA2LSB || header.e_type != ET_DYN) {
		return reject(path, "not a supported shared-object representation");
	}
	std::size_t exports = 0;
	Elf_Scn *section = nullptr;
	while ((section = ::elf_nextscn(elf.get(), section)) != nullptr) {
		GElf_Shdr table{};
		if (::gelf_getshdr(section, &table) == nullptr) {
			return reject(path, "unreadable section");
		}
		if (table.sh_type != SHT_DYNAMIC && table.sh_type != SHT_DYNSYM && table.sh_type != SHT_SYMTAB) {
			continue;
		}
		if (table.sh_entsize == 0) {
			return reject(path, "zero table width");
		}
		Elf_Data *data = nullptr;
		while ((data = ::elf_getdata(section, data)) != nullptr) {
			const auto count = data->d_size / table.sh_entsize;
			if (data->d_size % table.sh_entsize != 0 ||
			    count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
				return reject(path, "invalid table extent");
			}
			for (std::size_t index = 0; index < count; ++index) {
				if (table.sh_type == SHT_DYNAMIC) {
					GElf_Dyn entry{};
					if (::gelf_getdyn(data, static_cast<int>(index), &entry) == nullptr) {
						return reject(path, "invalid dynamic entry");
					}
					if (entry.d_tag == DT_RPATH || entry.d_tag == DT_RUNPATH ||
					    (entry.d_tag == DT_FLAGS_1 && (entry.d_un.d_val & DF_1_NODELETE) != 0)) {
						return reject(path, "RPATH/RUNPATH or NODELETE entered the SDK image");
					}
					if (entry.d_tag == DT_NEEDED) {
						const char *name =
							::elf_strptr(elf.get(), table.sh_link, entry.d_un.d_val);
						if (name == nullptr) {
							return reject(path, "invalid dependency name");
						}
						const std::string_view needed(name);
						if (needed.find("dpdk") != std::string_view::npos ||
						    needed.starts_with("librte_") ||
						    needed.starts_with("libarchive.so") ||
						    needed.find("kinetum_provider") != std::string_view::npos) {
							return reject(
								path,
								"provider or packaging dependency entered the SDK image");
						}
					}
					continue;
				}
				GElf_Sym symbol{};
				if (::gelf_getsym(data, static_cast<int>(index), &symbol) == nullptr) {
					return reject(path, "invalid symbol");
				}
				const char *raw_name = ::elf_strptr(elf.get(), table.sh_link, symbol.st_name);
				if (raw_name == nullptr) {
					return reject(path, "invalid symbol name");
				}
				const std::string_view name(raw_name);
				if (GELF_ST_BIND(symbol.st_info) == STB_GNU_UNIQUE) {
					return reject(path, "GNU-unique storage prevents owned unload");
				}
				if (name.find("kinetum_provider") != std::string_view::npos ||
				    name.starts_with("rte_")) {
					return reject(path, "provider implementation symbol entered the SDK image");
				}
				if (table.sh_type == SHT_DYNSYM && symbol.st_shndx != SHN_UNDEF &&
				    (GELF_ST_BIND(symbol.st_info) == STB_GLOBAL ||
				     GELF_ST_BIND(symbol.st_info) == STB_WEAK) &&
				    (GELF_ST_VISIBILITY(symbol.st_other) == STV_DEFAULT ||
				     GELF_ST_VISIBILITY(symbol.st_other) == STV_PROTECTED)) {
					++exports;
					if (module && name != "kinetum_module_register") {
						return reject(path,
							      "module exported more than its registration authority");
					}
				}
			}
		}
	}
	if (module && exports != 1u) {
		return reject(path, "module registration export is missing");
	}
	return true;
}

/**
 * @brief Validate the descriptor while the module's exact load handle remains live.
 * @param image Live module load handle.
 * @param expected_id Independently authored expected semantic module identity.
 * @return True only for the exact fixture descriptor while its image remains loaded.
 */
bool registration_valid(void *image, const char *expected_id)
{
	using registration_fn = const kinetum_module *(*)();
	static_assert(sizeof(registration_fn) == sizeof(void *));
	(void)::dlerror();
	void *symbol = ::dlsym(image, "kinetum_module_register");
	if (symbol == nullptr || ::dlerror() != nullptr) {
		return false;
	}
	registration_fn registration = nullptr;
	std::memcpy(&registration, &symbol, sizeof(registration));
	const kinetum_module *value = registration();
	return value != nullptr && value->module_id != nullptr && value->module_version != nullptr &&
	       std::strcmp(value->module_id, expected_id) == 0 && std::strcmp(value->module_version, "1.0.0") == 0 &&
	       value->abi_version == KINETUM_MODULE_ABI_VERSION && value->mode == KINETUM_MODULE_PASSIVE &&
	       value->prepare_config != nullptr && value->activate_config != nullptr &&
	       value->retire_config != nullptr && value->process != nullptr && value->init != nullptr &&
	       value->fini != nullptr && value->ingest == nullptr && value->run == nullptr &&
	       value->on_control == nullptr;
}

/**
 * @brief Prove a completed close removed the image from the loader's live set.
 * @param path Exact previously loaded fixture path.
 * @return True only when RTLD_NOLOAD finds no remaining image.
 */
bool unloaded(const char *path)
{
	void *resident = ::dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_NOLOAD);
	if (resident == nullptr) {
		return true;
	}
	(void)::dlclose(resident);
	return reject(path, "image remained resident after its last owner closed");
}

}  // namespace

/**
 * @brief Inspect and load a module with its optional explicitly owned shared dependency.
 * @param argc Process argument count.
 * @param argv Module path and optional explicit shared-dependency path.
 * @return Zero only after ELF, registration, close and unload checks; two for usage errors.
 */
int main(int argc, char **argv)
{
	if (argc != 2 && argc != 3) {
		return 2;
	}
	if (!inspect(argv[1], true) || (argc == 3 && !inspect(argv[2], false))) {
		return 1;
	}
	void *dependency = argc == 3 ? ::dlopen(argv[2], RTLD_NOW | RTLD_LOCAL) : nullptr;
	if (argc == 3 && dependency == nullptr) {
		(void)reject(argv[2], ::dlerror());
		return 1;
	}
	void *module = ::dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	bool valid = module != nullptr &&
		     registration_valid(module, argc == 2 ? "example.sdk.canary.c" : "example.sdk.canary.cpp");
	if (module == nullptr) {
		(void)reject(argv[1], ::dlerror());
	} else if (!valid) {
		(void)reject(argv[1], "module descriptor or dependency state is invalid");
	}
	if (module != nullptr && ::dlclose(module) != 0) {
		valid = false;
	}
	if (dependency != nullptr && ::dlclose(dependency) != 0) {
		valid = false;
	}
	const bool module_unloaded = unloaded(argv[1]);
	const bool dependency_unloaded = argc == 2 || unloaded(argv[2]);
	return valid && module_unloaded && dependency_unloaded ? 0 : 1;
}
