#ifndef ROOTHIDE_DYLD_TASK_METADATA_POLICY_H
#define ROOTHIDE_DYLD_TASK_METADATA_POLICY_H

#include <stdint.h>
#include <stddef.h>

// Darwin 25 / XNU 12377 task layout places uint32_t t_flags and uint32_t
// t_procflags in the qword immediately before all_image_info_addr/size.
// task_set_dyld_info() uses bit 22 to make the dyld metadata final.
#define TF_DYLD_ALL_IMAGE_FINAL 0x00400000U

static inline uint64_t task_dyld_flags_address_from_pair(uint64_t pairAddress)
{
    return pairAddress >= sizeof(uint64_t) ? pairAddress - sizeof(uint64_t) : 0;
}

static inline uint32_t task_dyld_flags_for_replacement(uint32_t flags)
{
    return flags & ~TF_DYLD_ALL_IMAGE_FINAL;
}

#endif
