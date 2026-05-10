#pragma once
#include <string>
#include <fstream>
#include <cstdint>
#include <vector>

#pragma pack(push, 1)
struct Superblock {
    uint32_t magic = 0x53564633; // "SVF3"
    uint32_t blockSize = 4096;
    uint32_t totalBlocks = 10000;  // roughly 40MB
    uint32_t totalInodes = 1000;
    uint32_t freeBlocks;
    uint32_t freeInodes;
    uint32_t inodeBitmapBlock = 1;
    uint32_t dataBitmapBlock = 2;
    uint32_t inodeTableBlock = 3;
    uint32_t rootDirectoryBlock = 35; 
    uint32_t dataStartBlock = 36;
};
#pragma pack(pop)

class VirtualDisk {
private:
    std::string diskFilePath;
    std::fstream diskFile;
    Superblock superblock;

    // Bitmaps in memory
    std::vector<uint8_t> inodeBitmap;
    std::vector<uint8_t> dataBitmap;

    void createEmptyDisk();
    void writeSuperblock();
    void writeBitmaps();
    
public:
    VirtualDisk(const std::string& filePath = "svf_disk.img");
    ~VirtualDisk();

    bool mount();
    void format();

    bool readBlock(uint32_t blockNum, char* buffer);
    bool writeBlock(uint32_t blockNum, const char* buffer);

    uint32_t allocateBlock();
    void freeBlock(uint32_t blockNum);
    
    uint32_t allocateInode();
    void freeInode(uint32_t inodeNum);
    
    // Inode Table Persistence
    bool readInode(uint32_t inodeNum, struct DiskInode& inode);
    bool writeInode(uint32_t inodeNum, const struct DiskInode& inode);
    
    Superblock getSuperblock() const { return superblock; }
};
