#ifndef RH_NAMECACHE_TRANSACTION_H
#define RH_NAMECACHE_TRANSACTION_H

#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

enum { RH_NAMECACHE_MAX_WRITES = 48 };

struct rh_namecache_write {
    uint64_t address;
    uint64_t old_value;
    uint64_t new_value;
    uint8_t size;
};

struct rh_namecache_transaction {
    struct rh_namecache_write writes[RH_NAMECACHE_MAX_WRITES];
    size_t count;
};

static int rh_namecache_read32(uint64_t address, uint32_t *value)
{
    if (!address || !value || kreadbuf(address, value, sizeof(*value)) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_read64(uint64_t address, uint64_t *value)
{
    if (!address || !value || kreadbuf(address, value, sizeof(*value)) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_expect64(uint64_t address, uint64_t expected)
{
    uint64_t observed = 0;
    if (rh_namecache_read64(address, &observed) != 0 || observed != expected) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int rh_namecache_writer_lock(void)
{
    uint64_t lock = ksymbol(namecache_rw_lock);
    uint64_t lock_exclusive = ksymbol(lck_rw_lock_exclusive);
    if (!lock || !lock_exclusive || !is_kcall_initialized()) {
        errno = ENOTSUP;
        return -1;
    }
    uint64_t arguments[] = { lock };
    if (kcall(NULL, lock_exclusive, 1, arguments) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_writer_unlock(void)
{
    uint64_t lock = ksymbol(namecache_rw_lock);
    uint64_t lock_done = ksymbol(lck_rw_done);
    if (!lock || !lock_done || !is_kcall_initialized()) {
        errno = ENOTSUP;
        return -1;
    }
    uint64_t arguments[] = { lock };
    if (kcall(NULL, lock_done, 1, arguments) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_retain_vnode(uint64_t vnode)
{
    uint64_t vnode_ref_ext = ksymbol(vnode_ref_ext);
    if (!vnode || !vnode_ref_ext || !is_kcall_initialized()) {
        errno = ENOTSUP;
        return -1;
    }
    uint64_t result = 0;
    uint64_t arguments[] = { vnode, 0, 0 };
    if (kcall(&result, vnode_ref_ext, 3, arguments) != 0) {
        errno = EIO;
        return -1;
    }
    if (result != 0) {
        errno = result <= INT_MAX ? (int)result : EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_release_vnode(uint64_t vnode)
{
    uint64_t vnode_rele_ext = ksymbol(vnode_rele_ext);
    if (!vnode || !vnode_rele_ext || !is_kcall_initialized()) {
        errno = ENOTSUP;
        return -1;
    }
    uint64_t arguments[] = { vnode, 0, 0 };
    if (kcall(NULL, vnode_rele_ext, 3, arguments) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_write_value(struct rh_namecache_transaction *transaction,
                                    uint64_t address, uint64_t value, uint8_t size)
{
    if (!transaction || !address || (size != sizeof(uint32_t) && size != sizeof(uint64_t)) ||
        transaction->count >= RH_NAMECACHE_MAX_WRITES) {
        errno = EINVAL;
        return -1;
    }

    struct rh_namecache_write *write = &transaction->writes[transaction->count];
    uint64_t old_value = 0;
    if (kreadbuf(address, &old_value, size) != 0) {
        errno = EIO;
        return -1;
    }

    write->address = address;
    write->old_value = old_value;
    write->new_value = value;
    write->size = size;
    transaction->count++;

    int result = size == sizeof(uint32_t) ? kwrite32(address, (uint32_t)value) : kwrite64(address, value);
    if (result != 0) {
        errno = EIO;
        return -1;
    }

    uint64_t observed = 0;
    if (kreadbuf(address, &observed, size) != 0 ||
        (size == sizeof(uint32_t) ? (uint32_t)observed != (uint32_t)value : observed != value)) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_write32(struct rh_namecache_transaction *transaction, uint64_t address, uint32_t value)
{
    return rh_namecache_write_value(transaction, address, value, sizeof(value));
}

static int rh_namecache_write64(struct rh_namecache_transaction *transaction, uint64_t address, uint64_t value)
{
    return rh_namecache_write_value(transaction, address, value, sizeof(value));
}

static int rh_namecache_transaction_matches_new(const struct rh_namecache_transaction *transaction)
{
    if (!transaction) return -1;
    for (size_t i = 0; i < transaction->count; i++) {
        const struct rh_namecache_write *write = &transaction->writes[i];
        bool superseded = false;
        for (size_t j = i + 1; j < transaction->count; j++) {
            if (transaction->writes[j].address == write->address) {
                superseded = true;
                break;
            }
        }
        if (superseded) continue;
        uint64_t observed = 0;
        if (kreadbuf(write->address, &observed, write->size) != 0 ||
            (write->size == sizeof(uint32_t)
                ? (uint32_t)observed != (uint32_t)write->new_value
                : observed != write->new_value)) {
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

static int rh_namecache_transaction_matches_old(const struct rh_namecache_transaction *transaction)
{
    if (!transaction) return -1;
    for (size_t i = 0; i < transaction->count; i++) {
        const struct rh_namecache_write *write = &transaction->writes[i];
        bool already_checked = false;
        for (size_t j = 0; j < i; j++) {
            if (transaction->writes[j].address == write->address) {
                already_checked = true;
                break;
            }
        }
        if (already_checked) continue;
        uint64_t observed = 0;
        if (kreadbuf(write->address, &observed, write->size) != 0 ||
            (write->size == sizeof(uint32_t)
                ? (uint32_t)observed != (uint32_t)write->old_value
                : observed != write->old_value)) {
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

static int rh_namecache_transaction_rollback(const struct rh_namecache_transaction *transaction)
{
    if (!transaction) return -1;
    int result = 0;
    for (size_t i = transaction->count; i > 0; i--) {
        const struct rh_namecache_write *write = &transaction->writes[i - 1];
        int write_result = write->size == sizeof(uint32_t)
            ? kwrite32(write->address, (uint32_t)write->old_value)
            : kwrite64(write->address, write->old_value);
        uint64_t observed = 0;
        if (write_result != 0 || kreadbuf(write->address, &observed, write->size) != 0 ||
            (write->size == sizeof(uint32_t)
                ? (uint32_t)observed != (uint32_t)write->old_value
                : observed != write->old_value)) {
            result = -1;
        }
    }
    if (result != 0) errno = EIO;
    return result;
}

static int rh_namecache_counter_invalidate(uint64_t address, uint32_t expected_valid)
{
    if (!(expected_valid & 1U)) {
        errno = EINVAL;
        return -1;
    }
    uint32_t observed = 0;
    if (rh_namecache_read32(address, &observed) != 0 || observed != expected_valid) {
        errno = EIO;
        return -1;
    }
    int write_result = kwrite32(address, expected_valid + 1U);
    if (rh_namecache_read32(address, &observed) == 0 && observed == expected_valid + 1U) return 0;
    if (write_result != 0 || observed != expected_valid + 1U) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int rh_namecache_counter_publish(uint64_t address, uint32_t expected_invalid)
{
    if (expected_invalid & 1U) {
        errno = EINVAL;
        return -1;
    }
    uint32_t observed = 0;
    if (rh_namecache_read32(address, &observed) != 0 || observed != expected_invalid) {
        errno = EIO;
        return -1;
    }
    int write_result = kwrite32(address, expected_invalid + 1U);
    if (rh_namecache_read32(address, &observed) == 0 && observed == expected_invalid + 1U) return 0;
    if (write_result != 0 || observed != expected_invalid + 1U) {
        errno = EIO;
        return -1;
    }
    return 0;
}

#endif
