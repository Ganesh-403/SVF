#include "svf/storage/BTree.h"
#include <iostream>
#include <cstring>
#include <algorithm>

BTreeDirectory::BTreeDirectory(VirtualDisk& disk, uint32_t rootBlock) 
    : disk(disk), rootBlockId(rootBlock) {
    if (rootBlockId == 0) {
        // Allocate a new block for the root
        rootBlockId = disk.allocateBlock();
        BTreeNode root;
        root.blockId = rootBlockId;
        root.isLeaf = true;
        root.numKeys = 0;
        memset(root.children, 0, sizeof(root.children));
        disk.writeBlock(rootBlockId, reinterpret_cast<const char*>(&root));
    }
}

void BTreeDirectory::splitChild(BTreeNode& parent, int i, BTreeNode& y) {
    uint32_t zBlock = disk.allocateBlock();
    if (zBlock == 0) {
        std::cerr << "ERROR: Disk full, cannot split B-Tree node.\n";
        return;
    }
    
    BTreeNode z;
    z.blockId = zBlock;
    z.isLeaf = y.isLeaf;
    
    int t = MAX_BTREE_DEGREE / 2; // t = 32
    z.numKeys = t - 1; // 31 keys
    
    // Copy the second half of y's keys to z
    for (int j = 0; j < t - 1; j++) {
        z.entries[j] = y.entries[j + t];
    }
    
    // Copy the second half of y's children to z
    if (!y.isLeaf) {
        for (int j = 0; j < t; j++) {
            z.children[j] = y.children[j + t];
        }
    }
    
    y.numKeys = t - 1;
    
    // Shift parent's children to make room for z
    for (int j = parent.numKeys; j >= i + 1; j--) {
        parent.children[j + 1] = parent.children[j];
    }
    parent.children[i + 1] = z.blockId;
    
    // Shift parent's keys to make room for the promoted key
    for (int j = parent.numKeys - 1; j >= i; j--) {
        parent.entries[j + 1] = parent.entries[j];
    }
    parent.entries[i] = y.entries[t - 1];
    parent.numKeys++;
    
    // Save all modified nodes to disk
    disk.writeBlock(y.blockId, reinterpret_cast<const char*>(&y));
    disk.writeBlock(z.blockId, reinterpret_cast<const char*>(&z));
    disk.writeBlock(parent.blockId, reinterpret_cast<const char*>(&parent));
}

void BTreeDirectory::insertNonFull(BTreeNode& node, const DirectoryEntry& entry) {
    int i = node.numKeys - 1;
    
    if (node.isLeaf) {
        // Shift keys to make space
        while (i >= 0 && std::strcmp(entry.fileName, node.entries[i].fileName) < 0) {
            node.entries[i + 1] = node.entries[i];
            i--;
        }
        node.entries[i + 1] = entry;
        node.numKeys++;
        disk.writeBlock(node.blockId, reinterpret_cast<const char*>(&node));
    } else {
        // Find the child
        while (i >= 0 && std::strcmp(entry.fileName, node.entries[i].fileName) < 0) {
            i--;
        }
        i++;
        
        BTreeNode child;
        disk.readBlock(node.children[i], reinterpret_cast<char*>(&child));
        
        if (child.numKeys == MAX_BTREE_DEGREE - 1) {
            splitChild(node, i, child);
            if (std::strcmp(entry.fileName, node.entries[i].fileName) > 0) {
                i++;
            }
            disk.readBlock(node.children[i], reinterpret_cast<char*>(&child));
        }
        insertNonFull(child, entry);
    }
}

void BTreeDirectory::insert(const std::string& fileName, uint32_t inodeId) {
    BTreeNode root;
    disk.readBlock(rootBlockId, reinterpret_cast<char*>(&root));
    
    DirectoryEntry entry;
    entry.inodeId = inodeId;
    std::strncpy(entry.fileName, fileName.c_str(), sizeof(entry.fileName) - 1);
    entry.fileName[sizeof(entry.fileName) - 1] = '\0';
    
    if (root.numKeys == MAX_BTREE_DEGREE - 1) {
        // Root is full, need a new root
        uint32_t newRootBlock = disk.allocateBlock();
        BTreeNode newRoot;
        newRoot.blockId = newRootBlock;
        newRoot.isLeaf = false;
        newRoot.numKeys = 0;
        newRoot.children[0] = rootBlockId;
        
        // Split the old root
        splitChild(newRoot, 0, root);
        
        // Insert into the new root
        insertNonFull(newRoot, entry);
        
        // Update rootBlockId
        rootBlockId = newRootBlock;
    } else {
        insertNonFull(root, entry);
    }
}

uint32_t BTreeDirectory::search(const std::string& fileName) {
    uint32_t currentBlock = rootBlockId;
    
    while (currentBlock != 0) {
        BTreeNode node;
        disk.readBlock(currentBlock, reinterpret_cast<char*>(&node));
        
        int i = 0;
        while (i < node.numKeys && std::strcmp(fileName.c_str(), node.entries[i].fileName) > 0) {
            i++;
        }
        
        if (i < node.numKeys && std::strcmp(fileName.c_str(), node.entries[i].fileName) == 0) {
            return node.entries[i].inodeId;
        }
        
        if (node.isLeaf) {
            return 0; // Not found
        }
        
        currentBlock = node.children[i];
    }
    
    return 0;
}

// Recursively traverse the tree to collect all entries
void collectEntries(VirtualDisk& disk, uint32_t blockId, std::vector<DirectoryEntry>& result) {
    if (blockId == 0) return;
    
    BTreeNode node;
    disk.readBlock(blockId, reinterpret_cast<char*>(&node));
    
    for (int i = 0; i < node.numKeys; i++) {
        if (!node.isLeaf) {
            collectEntries(disk, node.children[i], result);
        }
        result.push_back(node.entries[i]);
    }
    
    if (!node.isLeaf) {
        collectEntries(disk, node.children[node.numKeys], result);
    }
}

std::vector<DirectoryEntry> BTreeDirectory::listAll() {
    std::vector<DirectoryEntry> result;
    collectEntries(disk, rootBlockId, result);
    return result;
}
