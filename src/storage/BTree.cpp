#include "svf/storage/BTree.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <memory>

static bool readBTreeNode(VirtualDisk& disk, uint32_t blockId, BTreeNode& node) {
    if (blockId == 0) return false;
    char buffer[4096];
    if (!disk.readBlock(blockId, buffer)) {
        return false;
    }
    std::memset(&node, 0, sizeof(BTreeNode));
    std::memcpy(&node, buffer, sizeof(BTreeNode));
    return true;
}

static bool writeBTreeNode(VirtualDisk& disk, uint32_t blockId, const BTreeNode& node) {
    if (blockId == 0) return false;
    char buffer[4096];
    std::memset(buffer, 0, sizeof(buffer));
    std::memcpy(buffer, &node, sizeof(BTreeNode));
    return disk.writeBlock(blockId, buffer);
}

BTreeDirectory::BTreeDirectory(VirtualDisk& disk, uint32_t rootBlock) 
    : disk(disk), rootBlockId(rootBlock) {
    if (rootBlockId == 0) {
        rootBlockId = disk.allocateBlock();
        BTreeNode root;
        std::memset(&root, 0, sizeof(BTreeNode));
        root.blockId = rootBlockId;
        root.isLeaf = true;
        root.numKeys = 0;
        writeBTreeNode(disk, rootBlockId, root);
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
    
    writeBTreeNode(disk, y.blockId, y);
    writeBTreeNode(disk, z.blockId, z);
    writeBTreeNode(disk, parent.blockId, parent);
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
        writeBTreeNode(disk, node.blockId, node);
    } else {
        while (i >= 0 && std::strcmp(entry.fileName, node.entries[i].fileName) < 0) {
            i--;
        }
        i++;
        
        BTreeNode child;
        if (!readBTreeNode(disk, node.children[i], child)) {
            std::cerr << "ERROR: Failed to read B-Tree child node at block " << node.children[i] << "\n";
            return;
        }
        
        if (child.numKeys == MAX_BTREE_DEGREE - 1) {
            splitChild(node, i, child);
            if (std::strcmp(entry.fileName, node.entries[i].fileName) > 0) {
                i++;
            }
            if (!readBTreeNode(disk, node.children[i], child)) {
                std::cerr << "ERROR: Failed to read B-Tree child node after split at block " << node.children[i] << "\n";
                return;
            }
        }
        insertNonFull(child, entry);
    }
}

void BTreeDirectory::insert(const std::string& fileName, uint32_t inodeId) {
    BTreeNode root;
    if (!readBTreeNode(disk, rootBlockId, root)) {
        std::cerr << "ERROR: Failed to read B-Tree root block " << rootBlockId << "\n";
        return;
    }
    
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
        if (!readBTreeNode(disk, currentBlock, node)) {
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
    if (blockId == 0) return;
    if (recursionDepth > 64) {
        std::cerr << "ERROR: B-Tree recursion depth limit exceeded in listAll\n";
        return;
    }
    
    auto node = std::make_unique<BTreeNode>();
    if (!readBTreeNode(disk, blockId, *node)) {
        return;
    }
    
    if (node->blockId != blockId) {
        return; // Block ID mismatch guard
    }
    
    // Add all keys in the current node
    for (uint32_t i = 0; i < node->numKeys; ++i) {
        if (node->entries[i].inodeId != 0) {
            result.push_back(node->entries[i]);
        }
    }
    
    // Recurse into children
    if (!node->isLeaf) {
        for (uint32_t i = 0; i <= node->numKeys; ++i) {
            if (node->children[i] != 0) {
                collectEntriesRecursive(disk, node->children[i], result, recursionDepth + 1);
            }
        }
    }
}

static DirectoryEntry getPredecessor(VirtualDisk& disk, uint32_t blockId) {
    auto node = std::make_unique<BTreeNode>();
    if (!readBTreeNode(disk, blockId, *node)) {
        return DirectoryEntry{0, ""};
    }
    while (!node->isLeaf) {
        uint32_t nextBlock = node->children[node->numKeys];
        if (!readBTreeNode(disk, nextBlock, *node)) {
            break;
        }
    }
    return node->entries[node->numKeys - 1];
}

static bool removeFromSubtree(VirtualDisk& disk, uint32_t blockId, const std::string& fileName) {
    if (blockId == 0) return false;
    
    auto node = std::make_unique<BTreeNode>();
    if (!readBTreeNode(disk, blockId, *node)) {
        return false;
    }
    
    // Find if the key exists in this node
    int i = 0;
    while (i < (int)node->numKeys) {
        char safeName[61];
        std::strncpy(safeName, node->entries[i].fileName, 60);
        safeName[60] = '\0';
        int cmp = std::strcmp(fileName.c_str(), safeName);
        if (cmp > 0) {
            i++;
        } else {
            break;
        }
    }
    
    bool found = false;
    if (i < (int)node->numKeys) {
        char safeName[61];
        std::strncpy(safeName, node->entries[i].fileName, 60);
        safeName[60] = '\0';
        if (std::strcmp(fileName.c_str(), safeName) == 0) {
            found = true;
        }
    }
    
    if (found) {
        if (node->isLeaf) {
            // Case 1: Key is in leaf node. Shift entries left.
            for (uint32_t j = i; j < node->numKeys - 1; ++j) {
                node->entries[j] = node->entries[j + 1];
            }
            node->numKeys--;
            writeBTreeNode(disk, blockId, *node);
            return true;
        } else {
            // Case 2: Key is in internal node.
            // Replace with predecessor.
            DirectoryEntry pred = getPredecessor(disk, node->children[i]);
            if (pred.inodeId == 0) {
                return false;
            }
            node->entries[i] = pred;
            writeBTreeNode(disk, blockId, *node);
            // Recursively delete the predecessor from the subtree.
            return removeFromSubtree(disk, node->children[i], pred.fileName);
        }
    } else {
        if (node->isLeaf) {
            return false; // Key not found
        }
        if (node->children[i] == 0) return false;
        // Recurse on the child that should contain the key
        return removeFromSubtree(disk, node->children[i], fileName);
    }
}

void BTreeDirectory::remove(const std::string& fileName) {
    try {
        removeFromSubtree(disk, rootBlockId, fileName);
    } catch (const std::exception& e) {
        std::cerr << "[BTREE] EXCEPTION in remove: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "[BTREE] UNKNOWN EXCEPTION in remove\n";
    }
}

std::vector<DirectoryEntry> BTreeDirectory::listAll() {
    std::vector<DirectoryEntry> result;
    result.reserve(100);
    
    try {
        collectEntriesRecursive(disk, rootBlockId, result, 0);
    } catch (const std::exception& e) {
        std::cerr << "[BTREE] EXCEPTION in listAll: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "[BTREE] UNKNOWN EXCEPTION in listAll\n";
    }
    
    return result;
}
