#pragma once
#include <string>
#include <chrono>
#include <cstdint>
#include <shared_mutex>

// POSIX-style Permission Bitmasks (Linux-like)
#define S_IRUSR 00400 // Read by owner
#define S_IWUSR 00200 // Write by owner
#define S_IXUSR 00100 // Execute by owner
#define S_IRGRP 00040 // Read by group
#define S_IWGRP 00020 // Write by group
#define S_IXGRP 00010 // Execute by group
#define S_IROTH 00004 // Read by others
#define S_IWOTH 00002 // Write by others
#define S_IXOTH 00001 // Execute by others

#define REGULAR 1
#define DIRECTORY 2

#pragma pack(push, 1)
struct DiskInode {
    uint32_t id;
    uint32_t size;
    uint16_t fileType; // REGULAR or DIRECTORY
    uint16_t mode; // POSIX permissions e.g., 0755
    char owner[32]; 
    uint64_t creationTime;
    uint64_t modificationTime;
    uint32_t directBlocks[12];
    uint32_t indirectBlock; // Points to a block containing 1024 uint32_t block pointers
};
#pragma pack(pop)

class Inode {
private:
    DiskInode data;
    std::string fileName;
    
    // Concurrency: Multiple readers, Single writer
    mutable std::shared_mutex rw_lock;

public:
    Inode(std::string name, uint32_t id, uint16_t posixMode, const std::string& ownerName, int type = REGULAR);
    Inode(std::string name, const DiskInode& diskData);

    DiskInode& getDiskData() { return data; }
    const std::string& getFileName() const { return fileName; }
    
    // Thread-safe locking mechanisms for multi-client access
    void lockRead() const { rw_lock.lock_shared(); }
    void unlockRead() const { rw_lock.unlock_shared(); }
    void lockWrite() { rw_lock.lock(); }
    void unlockWrite() { rw_lock.unlock(); }

    uint32_t getBlockPointer(int index) const {
        if (index >= 0 && index < 12) return data.directBlocks[index];
        return 0; // Handled dynamically for indirect blocks
    }
    
    void setBlockPointer(int index, uint32_t blockNum) {
        if (index >= 0 && index < 12) data.directBlocks[index] = blockNum;
    }
    
    uint32_t getIndirectBlock() const { return data.indirectBlock; }
    void setIndirectBlock(uint32_t blockNum) { data.indirectBlock = blockNum; }
    
    uint16_t getMode() const { return data.mode; }
    void setMode(uint16_t newMode) { data.mode = newMode; }
    
    std::string getOwner() const { return std::string(data.owner); }
    int getFileType() const { return data.fileType; }
    uint32_t getSize() const { return data.size; }
    void setSize(uint32_t s) { data.size = s; }
};
