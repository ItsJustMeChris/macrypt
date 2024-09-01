// integrity_check.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <vector>
#include <libkern/OSCacheControl.h>
#include "string"

struct PageInfo
{
    uintptr_t start;
    uintptr_t end;
    uintptr_t size;
    uint64_t hash;
    std::vector<uint8_t> data;
};

#define COMPILE_TIME_SEED (__TIME__[0] + __TIME__[1] + __TIME__[3] + __TIME__[4] + __TIME__[6] + __TIME__[7] + __DATE__[0] + __DATE__[1] + __DATE__[2] + __DATE__[3] + __DATE__[4] + __DATE__[5] + __DATE__[6])

#define ROTATE_LEFT(value, bits) ((value << bits) | (value >> (64 - bits)))

#define COMPILE_TIME_RANDOM_UINT64_1 \
    (uint64_t(ROTATE_LEFT(COMPILE_TIME_SEED, 16)) ^ 0xC96C5795D7870F42ULL)

#define COMPILE_TIME_RANDOM_UINT64_2 \
    (uint64_t(ROTATE_LEFT(COMPILE_TIME_SEED, 32)) ^ 0xD96C5795D7870F43ULL)

#define COMPILE_TIME_RANDOM_UINT64_3 \
    (uint64_t(ROTATE_LEFT(COMPILE_TIME_SEED, 48)) ^ 0xE96C5795D7870F44ULL)

std::vector<PageInfo> validated_pages;

// __attribute__((section("__RESTRICT,__restrict"), used)) const char restrict_data[] = "WhY dOeSnT mY dYlIb InJeCtIoN wOrK";
__attribute__((section("__DATA,__hash"), used)) static struct embedded_hash_placeholder_t
{
    uint64_t real_hash; // This will be overwritten by another program with the actual hash

    union
    {
        uint64_t fake_hash_1;
        uint64_t random_value_1;
    };

    union
    {
        uint64_t fake_hash_2;
        uint64_t random_value_2;
    };

    union
    {
        uint64_t fake_hash_3;
        uint64_t random_value_3;
    };

} embedded_hash_placeholder = {
    .real_hash = 0xFFFFFFFFFFFFFFFFULL, // Placeholder value to be overwritten
    .fake_hash_1 = COMPILE_TIME_RANDOM_UINT64_1,
    .fake_hash_2 = COMPILE_TIME_RANDOM_UINT64_2,
    .fake_hash_3 = COMPILE_TIME_RANDOM_UINT64_3};

__attribute__((always_inline)) inline uint64_t get_embedded_hash()
{
    return embedded_hash_placeholder.real_hash;
}

uint8_t key[] = {0x12, 0x34, 0x56, 0x78}; // Example key
__attribute__((always_inline)) inline uint8_t prng(uint8_t seed)
{
    return (seed * 1103515245 + 12345) & 0xFF;
}

// Key rotation encryption function
__attribute__((always_inline)) inline void encrypt_text_section(uint8_t *remap, size_t text_size, uint8_t *key, size_t key_length)
{
    uint8_t key_index = 0;

    for (size_t i = 0; i < text_size; i++)
    {
        uint8_t *byte = (uint8_t *)(remap + i);
        // XOR with the current key byte
        *byte = *byte ^ key[key_index];

        // Rotate key index
        key_index = (key_index + 1) % key_length;

        // Update the key using PRNG
        key[key_index] = prng(key[key_index]);
    }
}

static void another_init_function(void);

__attribute__((used))
__attribute__((section("__DATA,__mod_init_func"), retain)) static void (*another_init_function_ptr)(void) = another_init_function;

static void another_init_function(void)
{
    printf("Hello from another init function\n");
}

__attribute__((always_inline)) inline int inline_strcmp(const char *str1, const char *str2)
{
    // Calculate the length of both strings
    size_t len1 = 0;
    size_t len2 = 0;

    while (str1[len1] != '\0')
        ++len1;
    while (str2[len2] != '\0')
        ++len2;

    // If lengths are different, strings are not equal
    if (len1 != len2)
    {
        return len1 - len2;
    }

    // Compare strings character by character
    for (size_t i = 0; i < len1; ++i)
    {
        if (str1[i] != str2[i])
        {
            return (unsigned char)str1[i] - (unsigned char)str2[i];
        }
    }

    // Strings are equal
    return 0;
}

// forward declaration
static void my_init_function(void);

__attribute__((used))
__attribute__((section("__DATA,__mod_init_func"), retain)) static void (*my_init_function_ptr)(void) = my_init_function;

__attribute__((section("__TEXT,__init"), used)) static void my_init_function(void)
{
    Dl_info info;
    dladdr((const void *)&my_init_function, &info);
    const char *image_name = info.dli_fname;
    int image_index = -1;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
    {
        if (inline_strcmp(_dyld_get_image_name(i), image_name) == 0)
        {
            image_index = i;
            break;
        }
    }

    if (image_index == -1)
    {
        printf("Failed to find image index");
        return;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(image_index);
    const intptr_t slide = _dyld_get_image_vmaddr_slide(image_index);

    const size_t key_length = sizeof(key) / sizeof(key[0]);

    printf("Image header: %lx\n", (uintptr_t)header);

    const struct load_command *cmd = (const struct load_command *)((const char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0)
            {
                const struct section_64 *sec = (const struct section_64 *)((const char *)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++, sec++)
                {
                    if (strcmp(sec->sectname, "__text") == 0)
                    {
                        uintptr_t text_start = slide + sec->addr;
                        size_t text_size = sec->size;

                        printf("Text start: %lx\n", (uintptr_t)text_start);
                        printf("Text size: %lx\n", (uintptr_t)text_size);

                        // 1. Remap the page somewhere else
                        mach_vm_address_t remap;
                        vm_prot_t cur, max;
                        kern_return_t ret = mach_vm_remap(mach_task_self(), &remap, text_size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR, mach_task_self(), text_start, FALSE, &cur, &max, VM_INHERIT_NONE);
                        printf("mach_vm_remap: %s\n", mach_error_string(ret));

                        // 2. Reprotect the page to rw-
                        ret = mach_vm_protect(mach_task_self(), remap, text_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        printf("mach_vm_protect: %s\n", mach_error_string(ret));

                        // 3. Encrypt the text section
                        encrypt_text_section((uint8_t *)remap, text_size, key, key_length);

                        // 4. Flush the data cache
                        sys_dcache_flush((void *)remap, text_size);

                        // 5. Reprotect the page to r-x
                        ret = mach_vm_protect(mach_task_self(), remap, text_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
                        printf("mach_vm_protect: %s\n", mach_error_string(ret));

                        // 6. Invalidate the instruction cache
                        sys_icache_invalidate((void *)remap, text_size);

                        // 7. Remap the page back over the original
                        ret = mach_vm_remap(mach_task_self(), (mach_vm_address_t *)&text_start, text_size, 0, VM_FLAGS_OVERWRITE | VM_FLAGS_RETURN_DATA_ADDR, mach_task_self(), remap, FALSE, &cur, &max, VM_INHERIT_NONE);
                        printf("mach_vm_remap: %s\n", mach_error_string(ret));

                        printf("Patched text section at address: %lx\n", text_start);

                        return; // Exit the loop once the text section is handled
                    }
                }
            }
        }
        cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize);
    }
}

__attribute__((always_inline)) inline uint64_t fnv1a_64(const uint8_t *data, size_t length)
{
    const uint64_t FNV_prime = 0x100000001b3ULL;
    const uint64_t offset_basis = 0xcbf29ce484222325ULL;
    uint64_t hash = offset_basis;

    for (size_t i = 0; i < length; ++i)
    {
        hash ^= data[i];
        hash *= FNV_prime;
    }

    return hash;
}

__attribute__((always_inline)) inline uintptr_t get_dylib_base_address()
{
    // Use the index 0 if it's the main binary, adjust if you are targeting a specific dynamic library
    return reinterpret_cast<uintptr_t>(_dyld_get_image_header(0)) + _dyld_get_image_vmaddr_slide(0);
}

__attribute__((always_inline)) inline size_t macho_page_size()
{
    // Assuming the page size is 0x4000 (16 KB)
    return 0x4000;
}

__attribute__((always_inline)) inline void populate_validated_hashes()
{
    Dl_info info;
    dladdr((const void *)&populate_validated_hashes, &info);
    const char *image_name = info.dli_fname;
    int image_index = -1;
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
    {
        if (strcmp(_dyld_get_image_name(i), image_name) == 0)
        {
            image_index = i;
            break;
        }
    }

    if (image_index == -1)
    {
        printf("Failed to find image index\n");
        return;
    }

    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(image_index);
    const intptr_t slide = _dyld_get_image_vmaddr_slide(image_index);

    const struct load_command *cmd = (const struct load_command *)((const char *)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
            if (strcmp(seg->segname, "__TEXT") == 0)
            {
                const struct section_64 *sec = (const struct section_64 *)((const char *)seg + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++, sec++)
                {
                    if (strcmp(sec->sectname, "__text") == 0)
                    {
                        uintptr_t text_start = slide + sec->addr; // Use sec->addr instead of sec->offset
                        uintptr_t text_end = text_start + sec->size;

                        printf("text_start: %lx\n", text_start);
                        printf("text_end: %lx\n", text_end);

                        std::vector<uint8_t> page_data(sec->size);
                        memcpy(page_data.data(), (const void *)text_start, sec->size);

                        uint64_t hash = fnv1a_64(page_data.data(), sec->size);
                        printf("Computed hash: 0x%llx\n", hash);

                        PageInfo page_info;
                        page_info.start = text_start;
                        page_info.end = text_end;
                        page_info.size = sec->size;
                        page_info.hash = hash;
                        page_info.data = page_data;

                        validated_pages.push_back(page_info);
                    }
                }
            }
        }
        cmd = (const struct load_command *)((const char *)cmd + cmd->cmdsize);
    }
}

__attribute__((always_inline)) inline bool integrity_check()
{
    for (const auto &segment : validated_pages)
    {
        std::vector<uint8_t> current_data(segment.size);
        memcpy(current_data.data(), (const void *)(segment.start), segment.size);

        uint64_t current_hash = fnv1a_64(current_data.data(), segment.size);

        if (current_hash != segment.hash || current_hash != get_embedded_hash()) // You could do some more stuff here to make it a bit more complicated to just find your runtime hash in memory and replace it, like XORing the hash with some key or something.
        {
            printf("Integrity check failed. Mismatch in __TEXT segment at address: %lx expected hash: %llx, got: %llx === %llx\n", segment.start, segment.hash, current_hash, get_embedded_hash());
            return false;
        }
    }

    printf("Integrity check passed. All __TEXT segments match.\n");
    return true;
}

__attribute__((noinline)) int patchable_function(int a, int b)
{
    asm volatile(
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n");
    return a + b;
}

int main()
{
    populate_validated_hashes();
    printf("Address of patchable function: %lu\n", (uintptr_t)patchable_function); // This is to help prove that the integrity is integrity checked properly
    uint64_t embedded_hash = get_embedded_hash();
    printf("Func to patch address: %lu\n", (uintptr_t)patchable_function);

    std::cout << "Embedded hash: 0x" << std::hex << embedded_hash << std::endl;

    while (true)
    {
        bool integrity_passed = integrity_check();

        if (integrity_passed)
        {
            std::cout << "Integrity check passed!" << std::endl;
        }
        else
        {
            std::cout << "Integrity check failed!" << std::endl;
            return 1;
        }

        usleep(100000);
    }

    return 0;
}
