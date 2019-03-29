// From llvm/Support/MachO.h - The MachO file format
#ifndef LIEF_MACHO_STRUCTURES_H_
#define LIEF_MACHO_STRUCTURES_H_

#include <cstdint>

#include "LIEF/types.hpp"

#include "LIEF/MachO/enums.hpp"


// Swap 2 byte, 16 bit values:
#define Swap2Bytes(val) \
 ( (((val) >> 8) & 0x00FF) | (((val) << 8) & 0xFF00) )


// Swap 4 byte, 32 bit values:
#define Swap4Bytes(val) \
 ( (((val) >> 24) & 0x000000FF) | (((val) >>  8) & 0x0000FF00) | \
   (((val) <<  8) & 0x00FF0000) | (((val) << 24) & 0xFF000000) )



// Swap 8 byte, 64 bit values:
#define Swap8Bytes(val) \
 ( (((val) >> 56) & 0x00000000000000FF) | (((val) >> 40) & 0x000000000000FF00) | \
   (((val) >> 24) & 0x0000000000FF0000) | (((val) >>  8) & 0x00000000FF000000) | \
   (((val) <<  8) & 0x000000FF00000000) | (((val) << 24) & 0x0000FF0000000000) | \
   (((val) << 40) & 0x00FF000000000000) | (((val) << 56) & 0xFF00000000000000) )

namespace LIEF {
//! Namespace related to the LIEF's MachO module
namespace MachO {

  
struct mach_header {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  //uint32_t reserved; not for 32 bits
};

struct mach_header_64 {
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct segment_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct segment_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  char     segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
};

struct section_32 {
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
};

struct section_64 {
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
};

struct fvmlib {
  uint32_t name;
  uint32_t minor_version;
  uint32_t header_addr;
};

struct fvmlib_command {
  uint32_t  cmd;
  uint32_t cmdsize;
  struct fvmlib fvmlib;
};

struct dylib {
  uint32_t name;
  uint32_t timestamp;
  uint32_t current_version;
  uint32_t compatibility_version;
};

struct dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  struct dylib dylib;
};

struct sub_framework_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t umbrella;
};

struct sub_client_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t client;
};

struct sub_umbrella_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_umbrella;
};

struct sub_library_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t sub_library;
};

struct prebound_dylib_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t nmodules;
  uint32_t linked_modules;
};

struct dylinker_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
};

struct thread_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t flavor;
  uint32_t count;
};

struct routines_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t init_address;
  uint32_t init_module;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
  uint32_t reserved4;
  uint32_t reserved5;
  uint32_t reserved6;
};

struct routines_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t init_address;
  uint64_t init_module;
  uint64_t reserved1;
  uint64_t reserved2;
  uint64_t reserved3;
  uint64_t reserved4;
  uint64_t reserved5;
  uint64_t reserved6;
};

struct symtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t symoff;
  uint32_t nsyms;
  uint32_t stroff;
  uint32_t strsize;
};

struct dysymtab_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t iundefsym;
  uint32_t nundefsym;
  uint32_t tocoff;
  uint32_t ntoc;
  uint32_t modtaboff;
  uint32_t nmodtab;
  uint32_t extrefsymoff;
  uint32_t nextrefsyms;
  uint32_t indirectsymoff;
  uint32_t nindirectsyms;
  uint32_t extreloff;
  uint32_t nextrel;
  uint32_t locreloff;
  uint32_t nlocrel;
};

struct dylib_table_of_contents {
  uint32_t symbol_index;
  uint32_t module_index;
};

struct dylib_module_32 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_addr;
  uint32_t objc_module_info_size;
};

struct dylib_module_64 {
  uint32_t module_name;
  uint32_t iextdefsym;
  uint32_t nextdefsym;
  uint32_t irefsym;
  uint32_t nrefsym;
  uint32_t ilocalsym;
  uint32_t nlocalsym;
  uint32_t iextrel;
  uint32_t nextrel;
  uint32_t iinit_iterm;
  uint32_t ninit_nterm;
  uint32_t objc_module_info_size;
  uint64_t objc_module_info_addr;
};

struct dylib_reference {
  uint32_t isym:24,
           flags:8;
};

struct twolevel_hints_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t nhints;
};

struct twolevel_hint {
  uint32_t isub_image:8,
           itoc:24;
};

struct prebind_cksum_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cksum;
};

struct uuid_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint8_t uuid[16];
};

struct rpath_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t path;
};

struct linkedit_data_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t dataoff;
  uint32_t datasize;
};

struct data_in_code_entry {
  uint32_t offset;
  uint16_t length;
  uint16_t kind;
};

struct source_version_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t version;
};

struct encryption_info_command_32 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
  uint32_t pad;
};

struct version_min_command {
  uint32_t cmd;       // LC_VERSION_MIN_MACOSX or
                      // LC_VERSION_MIN_IPHONEOS
  uint32_t cmdsize;   // sizeof(struct version_min_command)
  uint32_t version;   // X.Y.Z is encoded in nibbles xxxx.yy.zz
  uint32_t sdk;       // X.Y.Z is encoded in nibbles xxxx.yy.zz
};

struct dyld_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t rebase_off;
  uint32_t rebase_size;
  uint32_t bind_off;
  uint32_t bind_size;
  uint32_t weak_bind_off;
  uint32_t weak_bind_size;
  uint32_t lazy_bind_off;
  uint32_t lazy_bind_size;
  uint32_t export_off;
  uint32_t export_size;
};

struct linker_option_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t count;
};

struct symseg_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t offset;
  uint32_t size;
};

struct ident_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct fvmfile_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t name;
  uint32_t header_addr;
};

struct tlv_descriptor_32 {
  uint32_t thunk;
  uint32_t key;
  uint32_t offset;
};

struct tlv_descriptor_64 {
  uint64_t thunk;
  uint64_t key;
  uint64_t offset;
};

struct tlv_descriptor {
  uintptr_t thunk;
  uintptr_t key;
  uintptr_t offset;
};

struct entry_point_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint64_t entryoff;
  uint64_t stacksize;
};

// Structs from <mach-o/fat.h>
struct fat_header {
  uint32_t magic;
  uint32_t nfat_arch;
};

struct fat_arch {
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
};

// Structs from <mach-o/reloc.h>
struct relocation_info {
  int32_t r_address;
  uint32_t r_symbolnum:24,
           r_pcrel:1,
           r_length:2,
           r_extern:1,
           r_type:4;
};


struct scattered_relocation_info {
  uint32_t r_address:24,
           r_type:4,
           r_length:2,
           r_pcrel:1,
           r_scattered:1;
  int32_t r_value;
};


// Structs NOT from <mach-o/reloc.h>, but that make LLVM's life easier
struct any_relocation_info {
  uint32_t r_word0, r_word1;
};

// Structs from <mach-o/nlist.h>
struct nlist_base {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
};

struct nlist_32 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  int16_t n_desc;
  uint32_t n_value;
};

struct nlist_64 {
  uint32_t n_strx;
  uint8_t n_type;
  uint8_t n_sect;
  uint16_t n_desc;
  uint64_t n_value;
};


struct x86_thread_state64_t {
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
  uint64_t cs;
  uint64_t fs;
  uint64_t gs;
};

struct x86_thread_state_t {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
  uint32_t edi;
  uint32_t esi;
  uint32_t ebp;
  uint32_t esp;
  uint32_t ss;
  uint32_t eflags;
  uint32_t eip;
  uint32_t cs;
  uint32_t ds;
  uint32_t es;
  uint32_t fs;
  uint32_t gs;
};

struct arm_thread_state_t {
  uint32_t r0;
  uint32_t r1;
  uint32_t r2;
  uint32_t r3;
  uint32_t r4;
  uint32_t r5;
  uint32_t r6;
  uint32_t r7;
  uint32_t r8;
  uint32_t r9;
  uint32_t r10;
  uint32_t r11;
  uint32_t r12;
  uint32_t r13;
  uint32_t r14;
  uint32_t r15;
  uint32_t r16;   /* Apple's thread_state has this 17th reg, bug?? */
};

struct arm_thread_state64_t {
  uint64_t x[29]; // x0-x28
  uint64_t fp;    // x29
  uint64_t lr;    // x30
  uint64_t sp;    // x31
  uint64_t pc;    // pc
  uint32_t cpsr;  // cpsr
};







  static const HEADER_FLAGS header_flags_array[] = {
    HEADER_FLAGS::MH_NOUNDEFS,              HEADER_FLAGS::MH_INCRLINK,
    HEADER_FLAGS::MH_DYLDLINK,              HEADER_FLAGS::MH_BINDATLOAD,
    HEADER_FLAGS::MH_PREBOUND,              HEADER_FLAGS::MH_SPLIT_SEGS,
    HEADER_FLAGS::MH_LAZY_INIT,             HEADER_FLAGS::MH_TWOLEVEL,
    HEADER_FLAGS::MH_FORCE_FLAT,            HEADER_FLAGS::MH_NOMULTIDEFS,
    HEADER_FLAGS::MH_NOFIXPREBINDING,       HEADER_FLAGS::MH_PREBINDABLE,
    HEADER_FLAGS::MH_ALLMODSBOUND,          HEADER_FLAGS::MH_SUBSECTIONS_VIA_SYMBOLS,
    HEADER_FLAGS::MH_CANONICAL,             HEADER_FLAGS::MH_WEAK_DEFINES,
    HEADER_FLAGS::MH_BINDS_TO_WEAK,         HEADER_FLAGS::MH_ALLOW_STACK_EXECUTION,
    HEADER_FLAGS::MH_ROOT_SAFE,             HEADER_FLAGS::MH_SETUID_SAFE,
    HEADER_FLAGS::MH_NO_REEXPORTED_DYLIBS,  HEADER_FLAGS::MH_PIE,
    HEADER_FLAGS::MH_DEAD_STRIPPABLE_DYLIB, HEADER_FLAGS::MH_HAS_TLV_DESCRIPTORS,
    HEADER_FLAGS::MH_NO_HEAP_EXECUTION,     HEADER_FLAGS::MH_APP_EXTENSION_SAFE
  };


  static const MACHO_SECTION_FLAGS section_flags_array[] = {
    MACHO_SECTION_FLAGS::S_ATTR_PURE_INSTRUCTIONS, MACHO_SECTION_FLAGS::S_ATTR_NO_TOC,
    MACHO_SECTION_FLAGS::S_ATTR_STRIP_STATIC_SYMS, MACHO_SECTION_FLAGS::S_ATTR_NO_DEAD_STRIP,
    MACHO_SECTION_FLAGS::S_ATTR_LIVE_SUPPORT,      MACHO_SECTION_FLAGS::S_ATTR_SELF_MODIFYING_CODE,
    MACHO_SECTION_FLAGS::S_ATTR_DEBUG,             MACHO_SECTION_FLAGS::S_ATTR_SOME_INSTRUCTIONS,
    MACHO_SECTION_FLAGS::S_ATTR_EXT_RELOC,         MACHO_SECTION_FLAGS::S_ATTR_LOC_RELOC
  };


  class MachO32 {
    public:
    using header                  = mach_header;
    using segment_command         = segment_command_32;
    using section                 = section_32;
    using routines_command        = routines_command_32;
    using dylib_module            = dylib_module_32;
    using encryption_info_command = encryption_info_command_32;
    using nlist                   = nlist_32;

    using uint                    = uint32_t;
  };

  class MachO64 {
    public:
    using header                  = mach_header_64;
    using segment_command         = segment_command_64;
    using section                 = section_64;
    using routines_command        = routines_command_64;
    using dylib_module            = dylib_module_64;
    using encryption_info_command = encryption_info_command_64;
    using nlist                   = nlist_64;

    using uint                    = uint64_t;
  };

} // end namespace MachO
}
#endif
