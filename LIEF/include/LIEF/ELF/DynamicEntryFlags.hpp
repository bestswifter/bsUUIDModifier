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
#ifndef LIEF_ELF_DYNAMIC_ENTRY_FLAGS_H_
#define LIEF_ELF_DYNAMIC_ENTRY_FLAGS_H_

#include <string>

#include "LIEF/visibility.h"

#include "LIEF/ELF/type_traits.hpp"
#include "LIEF/ELF/DynamicEntry.hpp"

namespace LIEF {
namespace ELF {
class DLL_PUBLIC DynamicEntryFlags : public DynamicEntry {

  public:
    using DynamicEntry::DynamicEntry;
    DynamicEntryFlags(void);

    DynamicEntryFlags& operator=(const DynamicEntryFlags&);
    DynamicEntryFlags(const DynamicEntryFlags&);

    //! @brief If the current entry has the given DYNAMIC_FLAGS
    bool has(DYNAMIC_FLAGS f) const;

    //! @brief If the current entry has the given DYNAMIC_FLAGS_1
    bool has(DYNAMIC_FLAGS_1 f) const;

    //! @brief Return flags as a list of integers
    dynamic_flags_list_t flags(void) const;

    //! @brief Add the given DYNAMIC_FLAGS
    void add(DYNAMIC_FLAGS f);

    //! @brief Add the given DYNAMIC_FLAGS_1
    void add(DYNAMIC_FLAGS_1 f);

    //! @brief Remove the given DYNAMIC_FLAGS
    void remove(DYNAMIC_FLAGS f);

    //! @brief Remove the given DYNAMIC_FLAGS_1
    void remove(DYNAMIC_FLAGS_1 f);

    DynamicEntryFlags& operator+=(DYNAMIC_FLAGS f);
    DynamicEntryFlags& operator+=(DYNAMIC_FLAGS_1 f);

    DynamicEntryFlags& operator-=(DYNAMIC_FLAGS f);
    DynamicEntryFlags& operator-=(DYNAMIC_FLAGS_1 f);

    //! @brief Method so that the ``visitor`` can visit us
    virtual void accept(Visitor& visitor) const override;

    virtual std::ostream& print(std::ostream& os) const override;
};
}
}

#endif
