#include "svf/vfs/Inode.h"
#include <cstring>

Inode::Inode(std::string name, uint32_t id, uint16_t posixMode, const std::string& ownerName, int type)
    : fileName(std::move(name)) {
    data.id = id;
    data.size = 0;
    data.fileType = type;
    data.mode = posixMode;
    
    // Safely copy owner name, ensuring null termination
    std::strncpy(data.owner, ownerName.c_str(), sizeof(data.owner) - 1);
    data.owner[sizeof(data.owner) - 1] = '\0';
    
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    
    data.creationTime = millis;
    data.modificationTime = millis;
    
    for (int i = 0; i < 12; ++i) {
        data.directBlocks[i] = 0; // 0 means unallocated
    }
}

Inode::Inode(std::string name, const DiskInode& diskData)
    : fileName(std::move(name)), data(diskData) {
}
