// hash_embedder.cpp
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

// Utility functions
uint64_t fnv1a_64(const uint8_t *data, size_t length)
{
    const uint64_t FNV_PRIME = 0x100000001b3ULL;
    const uint64_t OFFSET_BASIS = 0xcbf29ce484222325ULL;
    uint64_t hash = OFFSET_BASIS;

    for (size_t i = 0; i < length; ++i)
    {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

__attribute__((always_inline)) inline uint8_t prng(uint8_t seed)
{
    return (seed * 1103515245 + 12345) & 0xFF;
}

// Encryption function
__attribute__((always_inline)) inline void encrypt_text_section(uint8_t *remap, size_t text_size, uint8_t *key, size_t key_length)
{
    for (size_t i = 0, key_index = 0; i < text_size; i++)
    {
        remap[i] ^= key[key_index];
        key_index = (key_index + 1) % key_length;
        key[key_index] = prng(key[key_index]);
    }
}

// Mach-O processing functions
uint64_t compute_text_section_hash(const std::vector<uint8_t> &file_data, uint64_t &hash_offset, uint64_t &text_offset,
                                   uint64_t &text_end_offset, uint64_t &init_offsets, uint64_t &init_offsets_end,
                                   uint64_t &mod_init_funcs, uint64_t &mod_init_funcs_end, uint64_t &decrypt_init)
{
    const mach_header_64 *header = reinterpret_cast<const mach_header_64 *>(file_data.data());
    const load_command *cmd = reinterpret_cast<const load_command *>(file_data.data() + sizeof(mach_header_64));

    uint64_t hash = 0;

    for (uint32_t i = 0; i < header->ncmds; i++)
    {
        if (cmd->cmd == LC_SEGMENT_64)
        {
            const segment_command_64 *seg = reinterpret_cast<const segment_command_64 *>(cmd);
            const section_64 *sec = reinterpret_cast<const section_64 *>(seg + 1);

            for (uint32_t j = 0; j < seg->nsects; j++, sec++)
            {
                if (strcmp(seg->segname, "__TEXT") == 0 && strcmp(sec->sectname, "__text") == 0)
                {
                    uintptr_t text_start = reinterpret_cast<uintptr_t>(header) + sec->offset;
                    uintptr_t text_end = text_start + sec->size;
                    std::vector<uint8_t> page_data(sec->size);
                    memcpy(page_data.data(), reinterpret_cast<const void *>(text_start), sec->size);

                    hash = fnv1a_64(page_data.data(), sec->size);
                    text_offset = sec->offset;
                    text_end_offset = text_offset + sec->size;
                }
                else if (strcmp(seg->segname, "__DATA") == 0 && strcmp(sec->sectname, "__hash") == 0)
                {
                    hash_offset = sec->offset;
                }
                else if (strcmp(seg->segname, "__TEXT") == 0 && strcmp(sec->sectname, "__init_offsets") == 0)
                {
                    init_offsets = sec->offset;
                    init_offsets_end = init_offsets + sec->size;
                }
                else if (strcmp(seg->segname, "__TEXT") == 0 && strcmp(sec->sectname, "__init") == 0)
                {
                    decrypt_init = sec->offset;
                }
                else if (strcmp(seg->segname, "__DATA_CONST") == 0 && strcmp(sec->sectname, "__mod_init_func") == 0)
                {
                    mod_init_funcs = sec->offset;
                    mod_init_funcs_end = mod_init_funcs + sec->size;
                }
            }
        }
        cmd = reinterpret_cast<const load_command *>(reinterpret_cast<const uint8_t *>(cmd) + cmd->cmdsize);
    }

    return hash;
}

void embed_hash(const std::string &filename, uint64_t hash, uint64_t offset)
{
    std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }
    file.seekp(offset);
    file.write(reinterpret_cast<const char *>(&hash), sizeof(hash));
    file.close();

    std::cout << "Embedded hash into " << filename << " at offset: 0x" << std::hex << offset << std::endl;
}

void encrypt_binary(const std::string &filename, uint64_t offset, uint64_t end_offset)
{
    std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    file.seekp(offset);
    std::vector<uint8_t> data(end_offset - offset);
    file.read(reinterpret_cast<char *>(data.data()), data.size());

    uint8_t key[] = {0x12, 0x34, 0x56, 0x78};
    size_t key_length = sizeof(key) / sizeof(key[0]);

    encrypt_text_section(data.data(), data.size(), key, key_length);

    file.seekp(offset);
    file.write(reinterpret_cast<const char *>(data.data()), data.size());
    file.close();

    std::cout << "Encrypted binary " << filename << " from offset: 0x" << std::hex << offset << " to 0x" << end_offset << std::endl;
}

void reorder_init_offsets(const std::string &filename, uint64_t offset, uint64_t end_offset, uint64_t decrypt_init)
{
    std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    file.seekp(offset);
    std::vector<uint32_t> data((end_offset - offset) / sizeof(uint32_t));
    file.read(reinterpret_cast<char *>(data.data()), data.size() * sizeof(uint32_t));

    auto it = std::find(data.begin(), data.end(), decrypt_init);
    if (it != data.end())
    {
        std::rotate(data.begin(), it, it + 1);
    }

    file.seekp(offset);
    file.write(reinterpret_cast<const char *>(data.data()), data.size() * sizeof(uint32_t));
    file.close();

    std::cout << "Reordered __init_offsets in " << filename << " from offset: 0x" << std::hex << offset << " to 0x" << end_offset << std::endl;
}

void reorder_mod_init_funcs(const std::string &filename, uint64_t offset, uint64_t end_offset, uint64_t decrypt_init)
{
    std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    file.seekp(offset);
    std::vector<uint64_t> data((end_offset - offset) / sizeof(uint64_t));
    file.read(reinterpret_cast<char *>(data.data()), data.size() * sizeof(uint64_t));

    auto it = std::find(data.begin(), data.end(), decrypt_init);
    if (it != data.end())
    {
        std::rotate(data.begin(), it, it + 1);
    }

    file.seekp(offset);
    file.write(reinterpret_cast<const char *>(data.data()), data.size() * sizeof(uint64_t));
    file.close();

    std::cout << "Reordered __mod_init_funcs in " << filename << " from offset: 0x" << std::hex << offset << " to 0x" << end_offset << std::endl;
}

void process_macho(const std::vector<uint8_t> &data, const std::string &filename, uint64_t fat_offset = 0)
{
    uint64_t hash_offset = 0, text_start = 0, text_end = 0, init_offsets = 0, init_offsets_end = 0,
             mod_init_funcs = 0, mod_init_funcs_end = 0, decrypt_init = 0;

    uint64_t hash = compute_text_section_hash(data, hash_offset, text_start, text_end, init_offsets,
                                              init_offsets_end, mod_init_funcs, mod_init_funcs_end, decrypt_init);

    if (hash_offset > 0)
    {
        embed_hash(filename, hash, fat_offset + hash_offset);
    }
    else
    {
        std::cerr << "Failed to find __hash section in " << filename << std::endl;
    }

    if (init_offsets > 0 && init_offsets_end > 0 && decrypt_init > 0)
    {
        reorder_init_offsets(filename, fat_offset + init_offsets, fat_offset + init_offsets_end, decrypt_init);
    }
    else
    {
        std::cerr << "Failed to find __init_offsets section in " << filename << std::endl;
    }

    if (mod_init_funcs > 0 && mod_init_funcs_end > 0 && decrypt_init > 0)
    {
        reorder_mod_init_funcs(filename, fat_offset + mod_init_funcs, fat_offset + mod_init_funcs_end, decrypt_init);
    }
    else
    {
        std::cerr << "Failed to find __mod_init_funcs section in " << filename << std::endl;
    }

    if (text_start > 0)
    {
        encrypt_binary(filename, fat_offset + text_start, fat_offset + text_end);
    }
    else
    {
        std::cerr << "Failed to find __TEXT section in " << filename << std::endl;
    }

    std::cout << "Successfully computed and embedded hash of __TEXT section: 0x" << std::hex << hash << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <executable>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return 1;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    const fat_header *fat = reinterpret_cast<const fat_header *>(data.data());

    if (fat->magic == FAT_MAGIC || fat->magic == FAT_CIGAM)
    {
        uint32_t nfat_arch = ntohl(fat->nfat_arch);
        const fat_arch *archs = reinterpret_cast<const fat_arch *>(data.data() + sizeof(fat_header));

        for (uint32_t i = 0; i < nfat_arch; ++i)
        {
            const fat_arch *arch = &archs[i];
            uint64_t offset = ntohl(arch->offset);
            uint64_t size = ntohl(arch->size);

            std::vector<uint8_t> arch_data(data.begin() + offset, data.begin() + offset + size);
            process_macho(arch_data, filename, offset);
        }
    }
    else
    {
        process_macho(data, filename);
    }

    return 0;
}
