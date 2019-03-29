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
#ifndef LIEF_MACHO_ENUM_TO_STRING_H
#define LIEF_MACHO_ENUM_TO_STRING_H
#include "LIEF/visibility.h"

#include "LIEF/MachO/Structures.hpp"

namespace LIEF {
namespace MachO {
DLL_PUBLIC const char* to_string(LOAD_COMMAND_TYPES e);
DLL_PUBLIC const char* to_string(MACHO_TYPES e);
DLL_PUBLIC const char* to_string(FILE_TYPES e);
DLL_PUBLIC const char* to_string(CPU_TYPES e);
DLL_PUBLIC const char* to_string(HEADER_FLAGS e);
DLL_PUBLIC const char* to_string(MACHO_SECTION_TYPES e);
DLL_PUBLIC const char* to_string(MACHO_SECTION_FLAGS e);
DLL_PUBLIC const char* to_string(MACHO_SYMBOL_TYPES e);
DLL_PUBLIC const char* to_string(N_LIST_TYPES e);
DLL_PUBLIC const char* to_string(SYMBOL_DESCRIPTIONS e);

DLL_PUBLIC const char* to_string(X86_RELOCATION e);
DLL_PUBLIC const char* to_string(X86_64_RELOCATION e);
DLL_PUBLIC const char* to_string(PPC_RELOCATION e);
DLL_PUBLIC const char* to_string(ARM_RELOCATION e);
DLL_PUBLIC const char* to_string(ARM64_RELOCATION e);
DLL_PUBLIC const char* to_string(RELOCATION_ORIGINS e);

DLL_PUBLIC const char* to_string(REBASE_TYPES e);
DLL_PUBLIC const char* to_string(BINDING_CLASS e);
DLL_PUBLIC const char* to_string(REBASE_OPCODES e);
DLL_PUBLIC const char* to_string(BIND_TYPES e);
DLL_PUBLIC const char* to_string(BIND_SPECIAL_DYLIB e);
DLL_PUBLIC const char* to_string(BIND_OPCODES e);
DLL_PUBLIC const char* to_string(EXPORT_SYMBOL_KINDS e);
DLL_PUBLIC const char* to_string(VM_PROTECTIONS e);

} // namespace MachO
} // namespace LIEF

#endif
