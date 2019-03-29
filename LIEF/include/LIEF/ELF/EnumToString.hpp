/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef ELF_ENUM_TO_STRING_H_
#define ELF_ENUM_TO_STRING_H_
#include "LIEF/visibility.h"
#include "LIEF/ELF/Structures.hpp"

namespace LIEF {
namespace ELF {
DLL_PUBLIC const char* to_string(SYMBOL_BINDINGS e);
DLL_PUBLIC const char* to_string(E_TYPE e);
DLL_PUBLIC const char* to_string(VERSION e);
DLL_PUBLIC const char* to_string(ARCH e);
DLL_PUBLIC const char* to_string(SEGMENT_TYPES e);
DLL_PUBLIC const char* to_string(DYNAMIC_TAGS e);
DLL_PUBLIC const char* to_string(ELF_SECTION_TYPES e);
DLL_PUBLIC const char* to_string(ELF_SECTION_FLAGS e);
DLL_PUBLIC const char* to_string(ELF_SYMBOL_TYPES e);
DLL_PUBLIC const char* to_string(RELOC_x86_64 e);
DLL_PUBLIC const char* to_string(RELOC_ARM e);
DLL_PUBLIC const char* to_string(RELOC_i386 e);
DLL_PUBLIC const char* to_string(RELOC_AARCH64 e);
DLL_PUBLIC const char* to_string(ELF_CLASS e);
DLL_PUBLIC const char* to_string(ELF_DATA e);
DLL_PUBLIC const char* to_string(OS_ABI e);
DLL_PUBLIC const char* to_string(DYNSYM_COUNT_METHODS e);
DLL_PUBLIC const char* to_string(NOTE_TYPES e);
DLL_PUBLIC const char* to_string(NOTE_ABIS e);
DLL_PUBLIC const char* to_string(RELOCATION_PURPOSES e);
DLL_PUBLIC const char* to_string(IDENTITY e);
DLL_PUBLIC const char* to_string(SYMBOL_SECTION_INDEX e);
DLL_PUBLIC const char* to_string(DYNAMIC_FLAGS e);
DLL_PUBLIC const char* to_string(DYNAMIC_FLAGS_1 e);
DLL_PUBLIC const char* to_string(ELF_SEGMENT_FLAGS e);

DLL_PUBLIC const char* to_string(PPC64_EFLAGS e);
DLL_PUBLIC const char* to_string(ARM_EFLAGS e);
DLL_PUBLIC const char* to_string(MIPS_EFLAGS e);
DLL_PUBLIC const char* to_string(HEXAGON_EFLAGS e);


} // namespace ELF
} // namespace LIEF

#endif

