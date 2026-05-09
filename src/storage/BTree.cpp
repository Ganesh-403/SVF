#include "svf/storage/BTree.h"
#include <iostream>
#include <cstring>

BTreeDirectory::BTreeDirectory(VirtualDisk& disk, uint32_t rootBlock) 
    : disk(disk), rootBlockId(rootBlock) {
    if (rootBlockId == 0) {
        // Allocate a new block for the root
        rootBlockId = disk.allocateBlock();
        BTreeNode root;
        root.blockId = rootBlockId;
        root.isLeaf = true;
        root.numKeys = 0;
        disk.writeBlock(rootBlockId, reinterpret_cast<const char*>(&root));
    }
}

void BTreeDirectory::insert(const std::string& fileName, uint32_t inodeId) {
    BTreeNode root;
    disk.readBlock(rootBlockId, reinterpret_cast<char*>(&root));
    
    // Simplistic array insertion for demo purposes. 
    // A full B-Tree implementation requires splitting logic (`splitChild`)
    if (root.numKeys < MAX_BTREE_DEGREE - 1) {
        DirectoryEntry entry;
        entry.inodeId = inodeId;
        std::strncpy(entry.fileName, fileName.c_str(), sizeof(entry.fileName) - 1);
        entry.fileName[sizeof(entry.fileName) - 1] = '\0';
        
        root.entries[root.numKeys] = entry;
        root.numKeys++;
        
        disk.writeBlock(rootBlockId, reinterpret_cast<const char*>(&root));
        std::cout << "[B-Tree] Inserted " << fileName << " into Directory Block " << rootBlockId << "\n";
    } else {
        std::cerr << "[B-Tree] Root node full. Splitting not fully implemented in this stub.\n";
    }
}

uint32_t BTreeDirectory::search(const std::string& fileName) {
    BTreeNode root;
    disk.readBlock(rootBlockId, reinterpret_cast<char*>(&root));
    
    for (uint32_t i = 0; i < root.numKeys; i++) {
        if (std::strcmp(root.entries[i].fileName, fileName.c_str()) == 0) {
            return root.entries[i].inodeId;
        }
    }
    return 0; // Not found
}

std::vector<DirectoryEntry> BTreeDirectory::listAll() {
    BTreeNode root;
    disk.readBlock(rootBlockId, reinterpret_cast<char*>(&root));
    
    std::vector<DirectoryEntry> result;
    for (uint32_t i = 0; i < root.numKeys; i++) {
        result.push_back(root.entries[i]);
    }
    return result;
}
