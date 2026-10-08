#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../BaseBin/libjailbreak/src/roothider/dyld_task_metadata_policy.h"

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\n", __LINE__, #expr); return 1; } } while (0)

int main(void)
{
    CHECK(TF_DYLD_ALL_IMAGE_FINAL == 0x00400000U);
    CHECK(task_dyld_flags_address_from_pair(0x1008) == 0x1000);
    CHECK(task_dyld_flags_address_from_pair(sizeof(uint64_t) - 1) == 0);

    uint32_t original = 0xA5C12345U | TF_DYLD_ALL_IMAGE_FINAL;
    uint32_t replacement = task_dyld_flags_for_replacement(original);
    CHECK((replacement & TF_DYLD_ALL_IMAGE_FINAL) == 0);
    CHECK((replacement & ~TF_DYLD_ALL_IMAGE_FINAL) == (original & ~TF_DYLD_ALL_IMAGE_FINAL));

    uint32_t alreadyMutable = 0x81020304U & ~TF_DYLD_ALL_IMAGE_FINAL;
    CHECK(task_dyld_flags_for_replacement(alreadyMutable) == alreadyMutable);
    puts("dyld task metadata policy: 6 checks passed");
    return 0;
}
