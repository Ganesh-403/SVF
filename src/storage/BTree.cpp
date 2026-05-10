#include "svf/storage/BTree.h"
#include <iostream>
#include <cstring>
#include <algorithm>

BTreeDirectory::BTreeDirectory(VirtualDisk& disk, uint32_t rootBlock) 
    : disk(disk), rootBlockId(rootBlock) {
    if (rootBlockId == 0) {
        rootBlockId = disk.allocateBlock();
        BTreeNode root;
        std::memset(&root, 0, sizeof(BTreeNode));
        root.blockId = rootBlockId;
        root.isLeaf = true;
        root.numKeys = 0;
        disk.writeBlock(rootBlockId, reinterpret_cast<const char*>(&root));
    }
}

void BTreeDirectory::splitChild(BTreeNode& parent, int i, BTreeNode& y) {
    uint32_t zBlock = disk.allocateBlock();
    BTreeNode z;
    std::memset(&z, 0, sizeof(BTreeNode));
    z.blockId = zBlock;
    z.isLeaf = y.isLeaf;
    
    int t = MAX_BTREE_DEGREE / 2; 
    z.numKeys = t - 1; 
    
    for (int j = 0; j < t - 1; j++) {
        z.entries[j] = y.entries[j + t];
    }
    
    if (!y.isLeaf) {
        for (int j = 0; j < t; j++) {
            z.children[j] = y.children[j + t];
        }
    }
    
    y.numKeys = t - 1;
    
    for (int j = parent.numKeys; j >= i + 1; j--) {
        parent.children[j + 1] = parent.children[j];
    }
    parent.children[i + 1] = z.blockId;
    
    for (int j = parent.numKeys - 1; j >= i; j--) {
        parent.entries[j + 1] = parent.entries[j];
    }
    parent.entries[i] = y.entries[t - 1];
    parent.numKeys++;
    
    disk.writeBlock(y.blockId, reinterpret_cast<const char*>(&y));
    disk.writeBlock(z.blockId, reinterpret_cast<const char*>(&z));
    disk.writeBlock(parent.blockId, reinterpret_cast<const char*>(&parent));
}

void BTreeDirectory::insertNonFull(BTreeNode& node, const DirectoryEntry& entry) {
    int i = node.numKeys - 1;
    
    if (node.isLeaf) {
        while (i >= 0 && std::strcmp(entry.fileName, node.entries[i].fileName) < 0) {
            node.entries[i + 1] = node.entries[i];
            i--;
        }
        node.entries[i + 1] = entry;
        node.numKeys++;
        disk.writeBlock(node.blockId, reinterpret_cast<const char*>(&node));
    } else {
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
    std::memset(entry.fileName, 0, sizeof(entry.fileName));
    std::strncpy(entry.fileName, fileName.c_str(), sizeof(entry.fileName) - 1);
    
    if (root.numKeys == MAX_BTREE_DEGREE - 1) {
        uint32_t newRootBlock = disk.allocateBlock();
        BTreeNode newRoot;
        std::memset(&newRoot, 0, sizeof(BTreeNode));
        newRoot.blockId = newRootBlock;
        newRoot.isLeaf = false;
        newRoot.numKeys = 0;
        newRoot.children[0] = rootBlockId;
        
        splitChild(newRoot, 0, root);
        insertNonFull(newRoot, entry);
        rootBlockId = newRootBlock;
    } else {
        insertNonFull(root, entry);
    }
}

uint32_t BTreeDirectory::search(const std::string& fileName) {
    uint32_t currentBlock = rootBlockId;
    int iterationCount = 0;
    const int MAX_ITERATIONS = 128;
    
    while (currentBlock != 0 && iterationCount < MAX_ITERATIONS) {
        iterationCount++;
        
        BTreeNode node;
        if (!disk.readBlock(currentBlock, reinterpret_cast<char*>(&node))) {
            std::cerr << "ERROR: Failed to read B-Tree node at block " << currentBlock << "\n";
            return 0;
        }
        
        if (node.blockId != currentBlock) {
            std::cerr << "ERROR: B-Tree node blockId mismatch\n";
            return 0;
        }
        
        if (node.numKeys >= MAX_BTREE_DEGREE) {
            std::cerr << "ERROR: Invalid numKeys in B-Tree node\n";
            return 0;
        }
        
        int i = 0;
        while (i < (int)node.numKeys) {
            char safeName[61];
            std::strncpy(safeName, node.entries[i].fileName, 60);
            safeName[60] = '\0';
            
            int cmp = std::strcmp(fileName.c_str(), safeName);
            if (cmp > 0) {
                i++;
            } else {
                break;
            }
        }
        
        if (i < (int)node.numKeys) {
            char safeName[61];
            std::strncpy(safeName, node.entries[i].fileName, 60);
            safeName[60] = '\0';
            
            if (std::strcmp(fileName.c_str(), safeName) == 0) {
                if (node.entries[i].inodeId > 0 && node.entries[i].inodeId <= 1000) {
                    return node.entries[i].inodeId;
                } else {
                    std::cerr << "ERROR: Invalid inodeId found in search\n";
                    return 0;
                }
            }
        }
        
        if (node.isLeaf) return 0;
        
        if (i >= MAX_BTREE_DEGREE) {
            std::cerr << "ERROR: Index out of bounds when accessing children array\n";
            return 0;
        }
        
        currentBlock = node.children[i];
    }
    
    if (iterationCount >= MAX_ITERATIONS) {
        std::cerr << "ERROR: B-Tree search iteration limit exceeded. Possible infinite loop.\n";
    }
    
    return 0;
}

static void collectEntriesRecursive(VirtualDisk& disk, uint32_t blockId, 
                                     std::vector<DirectoryEntry>& result,
                                     int recursionDepth = 0) {
    std::cout << "[BTREE_REC] START blockId=" << blockId << " depth=" << recursionDepth << "\n";
    std::cout.flush();
    
    if (blockId == 0) {
        std::cout << "[BTREE_REC] blockId is 0, returning\n";
        std::cout.flush();
        return;
    }
    
    std::cout << "[BTREE_REC] About to allocate node\n";
    std::cout.flush();
    
    try {
        BTreeNode* node = new BTreeNode();
        std::cout << "[BTREE_REC] Node allocated\n";
        std::cout.flush();

        std::cout << "[BTREE_REC] About to read block\n";
        std::cout.flush();

        // Read into a raw block buffer to avoid overflowing the BTreeNode structure
        uint32_t blockSize = disk.getSuperblock().blockSize;
        char* raw = new char[blockSize];
        if (!disk.readBlock(blockId, raw)) {
            std::cout << "[BTREE_REC] readBlock failed\n";
            std::cout.flush();
            delete[] raw;
            delete node;
            return;
        }

        std::cout << "[BTREE_REC] Block read OK (raw)\n";
        std::cout.flush();

        // Safely copy only the size of the BTreeNode struct
        std::memset(node, 0, sizeof(BTreeNode));
        std::memcpy(node, raw, std::min<size_t>(sizeof(BTreeNode), blockSize));
        delete[] raw;

        if (node->numKeys == 0 && node->blockId == 0) {
            std::cout << "[BTREE_REC] Empty node, deleting and returning\n";
            std::cout.flush();
            delete node;
            return;
        }

        std::cout << "[BTREE_REC] About to delete node\n";
        std::cout.flush();
        delete node;

        std::cout << "[BTREE_REC] Node deleted, returning\n";
        std::cout.flush();
    } catch (...) {
        std::cout << "[BTREE_REC] EXCEPTION caught!\n";
        std::cout.flush();
    }
}

std::vector<DirectoryEntry> BTreeDirectory::listAll() {
    std::vector<DirectoryEntry> result;
    result.reserve(100);
    
    try {
        std::cout << "[BTREE] listAll() calling collectEntriesRecursive\n";
        std::cout.flush();
        collectEntriesRecursive(disk, rootBlockId, result, 0);
        std::cout << "[BTREE] listAll() collectEntriesRecursive returned\n";
        std::cout.flush();
    } catch (const std::exception& e) {
        std::cout << "[BTREE] EXCEPTION in listAll: " << e.what() << "\n";
        std::cout.flush();
    } catch (...) {
        std::cout << "[BTREE] UNKNOWN EXCEPTION in listAll\n";
        std::cout.flush();
    }
    
    return result;
}
