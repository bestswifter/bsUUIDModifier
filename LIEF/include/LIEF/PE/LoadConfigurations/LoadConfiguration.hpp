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
#ifndef LIEF_PE_LOAD_CONFIGURATION_H_
#define LIEF_PE_LOAD_CONFIGURATION_H_
#include <array>
#include <set>
#include <functional>
#include <algorithm>
#include <iostream>

#include "LIEF/Visitable.hpp"
#include "LIEF/visibility.h"

#include "LIEF/PE/Structures.hpp"

namespace LIEF {
namespace PE {

//! @brief Class modeling the default PE's ``LoadConfiguration``
//!
//! It's the base class for any future version of the structure
class DLL_PUBLIC LoadConfiguration : public Visitable {
  public:
  static constexpr WIN_VERSION VERSION = WIN_VERSION::WIN_UNKNOWN;
  static constexpr size_t PRINT_WIDTH = 45;

  LoadConfiguration(void);

  template<class T>
  LoadConfiguration(const load_configuration<T>* header);

  LoadConfiguration& operator=(const LoadConfiguration&);
  LoadConfiguration(const LoadConfiguration&);

  //! @brief (SDK) Version of the structure
  virtual WIN_VERSION version(void) const;

  //! @brief Characteristics of the structure
  //! It usually holds its size
  //!
  //! @see @link version LoadConfiguration::version@endlink
  uint32_t characteristics(void) const;

  //! @brief Date and time stamp value
  uint32_t timedatestamp(void) const;

  //! @brief Major Version
  uint16_t major_version(void) const;

  //! @brief Minor version
  uint16_t minor_version(void) const;

  //! @brief The global loader flags to clear for
  //! this process as the loader start the process.
  uint32_t global_flags_clear(void) const;

  //! @brief The global loader flags to set for
  //! this process as the loader starts the process.
  uint32_t global_flags_set(void) const;

  //! @brief The default timeout value to use for
  //! this process’s critical sections that are abandoned.
  uint32_t critical_section_default_timeout(void) const;

  //! @brief Memory that must be freed before
  //! it is returned to the system, in bytes.
  uint64_t decommit_free_block_threshold(void) const;

  //! @brief Total amount of free memory, in
  //! bytes.
  uint64_t decommit_total_free_threshold(void) const;

  //! @brief The VA of a list of
  //! addresses where the LOCK prefix
  //! is used so that they can be replaced with NOP on single
  //! processor machines.
  //!
  //! @warning For ``x86`` only
  uint64_t lock_prefix_table(void) const;

  //! @brief Maximum allocation size, in bytes.
  uint64_t maximum_allocation_size(void) const;

  //! @brief Maximum virtual memory size, in bytes.
  uint64_t virtual_memory_threshold(void) const;

  //! @brief Setting this field to a non-zero value is equivalent to calling
  //! ``SetProcessAffinityMask`` with this value during process startup (.exe only)
  uint64_t process_affinity_mask(void) const;

  //! @brief Process heap flags that correspond to the first argument of the
  //! ``HeapCreate`` function. These flags apply to the process heap that is
  //! created during process startup.
  uint32_t process_heap_flags(void) const;

  //! @brief The service pack version identifier.
  uint16_t csd_version(void) const;

  //! @brief Must be zero.
  uint16_t reserved1(void) const;

  //! @brief Reserved for use by the system.
  uint32_t editlist(void) const;

  //! @brief A pointer to a cookie that is used by Visual C++ or GS
  //! implementation.
  uint32_t security_cookie(void) const;


  void characteristics(uint32_t characteristics);
  void timedatestamp(uint32_t timedatestamp);

  void major_version(uint16_t major_version);
  void minor_version(uint16_t minor_version);

  void global_flags_clear(uint32_t global_flags_clear);
  void global_flags_set(uint32_t global_flags_set);

  void critical_section_default_timeout(uint32_t critical_section_default_timeout);

  void decommit_free_block_threshold(uint64_t decommit_free_block_threshold);
  void decommit_total_free_threshold(uint64_t decommit_total_free_threshold);

  void lock_prefix_table(uint64_t lock_prefix_table);
  void maximum_allocation_size(uint64_t maximum_allocation_size);
  void virtual_memory_threshold(uint64_t virtual_memory_threshold);
  void process_affinity_mask(uint64_t process_affinity_mask);
  void process_heap_flags(uint32_t process_heap_flagsid);
  void csd_version(uint16_t csd_version);
  void reserved1(uint16_t reserved1);
  void editlist(uint32_t editlist);
  void security_cookie(uint32_t security_cookie);

  virtual ~LoadConfiguration(void);

  virtual void accept(Visitor& visitor) const override;

  bool operator==(const LoadConfiguration& rhs) const;
  bool operator!=(const LoadConfiguration& rhs) const;

  virtual std::ostream& print(std::ostream& os) const;

  DLL_PUBLIC friend std::ostream& operator<<(std::ostream& os, const LoadConfiguration& config);


  protected:
  uint32_t characteristics_;
  uint32_t timedatestamp_;

  uint16_t major_version_;
  uint16_t minor_version_;

  uint32_t global_flags_clear_;
  uint32_t global_flags_set_;

  uint32_t critical_section_default_timeout_;

  uint64_t decommit_free_block_threshold_;
  uint64_t decommit_total_free_threshold_;

  uint64_t lock_prefix_table_;
  uint64_t maximum_allocation_size_;
  uint64_t virtual_memory_threshold_;
  uint64_t process_affinity_mask_;
  uint32_t process_heap_flags_;
  uint16_t csd_version_;
  uint16_t reserved1_;
  uint64_t editlist_;
  uint64_t security_cookie_;
};
}
}

#endif
