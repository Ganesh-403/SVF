#pragma once
#include "svf/storage/VirtualDisk.h"
#include <string>
#include <vector>
#include <cstdint>

#define MAX_BTREE_DEGREE 64

#pragma pack(push, 1)
struct DirectoryEntry {
    uint32_t inodeId;
    char fileName[60]; // 64 bytes total per entry
};

struct BTreeNode {
    uint32_t blockId;
    bool isLeaf;
    uint32_t numKeys;
    DirectoryEntry entries[MAX_BTREE_DEGREE - 1]; // Keys (FileName -> Inode)
    uint32_t children[MAX_BTREE_DEGREE]; // Block IDs of children
};
#pragma pack(pop)

class BTreeDirectory {
private:
    VirtualDisk& disk;
    uint32_t rootBlockId;

    void splitChild(BTreeNode& parent, int i, BTreeNode& y);
    void insertNonFull(BTreeNode& node, const DirectoryEntry& entry);

public:
    BTreeDirectory(VirtualDisk& disk, uint32_t rootBlock = 0);
    
    // Core B-Tree Operations mapped to Physical Disk Blocks
    void insert(const std::string& fileName, uint32_t inodeId);
    uint32_t search(const std::string& fileName);
    std::vector<DirectoryEntry> listAll();
    
    uint32_t getRootBlock() const { return rootBlockId; }
};
