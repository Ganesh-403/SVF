#include "svf/storage/VirtualDisk.h"
#include <iostream>
#include <cstring>

VirtualDisk::VirtualDisk(const std::string& filePath) : diskFilePath(filePath) {
}

VirtualDisk::~VirtualDisk() {
    if (diskFile.is_open()) {
        writeBitmaps();
        diskFile.close();
    }
}

void VirtualDisk::createEmptyDisk() {
    std::ofstream newDisk(diskFilePath, std::ios::binary);
    if (!newDisk) {
        std::cerr << "ERROR: Failed to create disk image.\n";
        return;
    }
    
    // Allocate sparse file roughly size of total blocks * block size
    size_t totalBytes = superblock.totalBlocks * superblock.blockSize;
    newDisk.seekp(totalBytes - 1);
    newDisk.write("", 1);
    newDisk.close();
}

void VirtualDisk::format() {
    createEmptyDisk();
    
    diskFile.open(diskFilePath, std::ios::in | std::ios::out | std::ios::binary);
    
    superblock.freeBlocks = superblock.totalBlocks - 4; // Reserve first 4 for SB, bitmaps, IT
    superblock.freeInodes = superblock.totalInodes;
    
    inodeBitmap.assign((superblock.totalInodes + 7) / 8, 0);
    dataBitmap.assign((superblock.totalBlocks + 7) / 8, 0);
    
    // Mark first 4 blocks as used in bitmap
    for(int i=0; i<4; i++) {
        dataBitmap[0] |= (1 << i);
    }
    
    writeSuperblock();
    writeBitmaps();
    std::cout << "Virtual Disk Formatted Successfully.\n";
}

bool VirtualDisk::mount() {
    diskFile.open(diskFilePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!diskFile.is_open()) {
        std::cout << "Disk image not found. Formatting new disk...\n";
        format();
        return true;
    }
    
    diskFile.seekg(0);
    diskFile.read(reinterpret_cast<char*>(&superblock), sizeof(Superblock));
    
    if (superblock.magic != 0x53564632) {
        std::cerr << "ERROR: Invalid filesystem magic number.\n";
        return false;
    }
    
    // Read bitmaps
    inodeBitmap.resize((superblock.totalInodes + 7) / 8);
    dataBitmap.resize((superblock.totalBlocks + 7) / 8);
    
    readBlock(superblock.inodeBitmapBlock, reinterpret_cast<char*>(inodeBitmap.data()));
    readBlock(superblock.dataBitmapBlock, reinterpret_cast<char*>(dataBitmap.data()));
    
    std::cout << "Virtual Disk Mounted Successfully. Free Blocks: " << superblock.freeBlocks << "\n";
    return true;
}

void VirtualDisk::writeSuperblock() {
    diskFile.seekp(0);
    diskFile.write(reinterpret_cast<const char*>(&superblock), sizeof(Superblock));
}

void VirtualDisk::writeBitmaps() {
    writeBlock(superblock.inodeBitmapBlock, reinterpret_cast<const char*>(inodeBitmap.data()));
    writeBlock(superblock.dataBitmapBlock, reinterpret_cast<const char*>(dataBitmap.data()));
}

bool VirtualDisk::readBlock(uint32_t blockNum, char* buffer) {
    if (blockNum >= superblock.totalBlocks) return false;
    diskFile.seekg(blockNum * superblock.blockSize);
    diskFile.read(buffer, superblock.blockSize);
    return true;
}

bool VirtualDisk::writeBlock(uint32_t blockNum, const char* buffer) {
    if (blockNum >= superblock.totalBlocks) return false;
    diskFile.seekp(blockNum * superblock.blockSize);
    diskFile.write(buffer, superblock.blockSize);
    return true;
}

uint32_t VirtualDisk::allocateBlock() {
    if (superblock.freeBlocks == 0) return 0; // Disk full
    
    for (size_t i = 0; i < dataBitmap.size(); ++i) {
        if (dataBitmap[i] != 0xFF) {
            for (int bit = 0; bit < 8; ++bit) {
                if ((dataBitmap[i] & (1 << bit)) == 0) {
                    dataBitmap[i] |= (1 << bit);
                    superblock.freeBlocks--;
                    writeSuperblock();
                    return i * 8 + bit;
                }
            }
        }
    }
    return 0;
}

void VirtualDisk::freeBlock(uint32_t blockNum) {
    if (blockNum < 4 || blockNum >= superblock.totalBlocks) return;
    
    size_t byteIdx = blockNum / 8;
    int bitIdx = blockNum % 8;
    
    if (dataBitmap[byteIdx] & (1 << bitIdx)) {
        dataBitmap[byteIdx] &= ~(1 << bitIdx);
        superblock.freeBlocks++;
        writeSuperblock();
    }
}

uint32_t VirtualDisk::allocateInode() {
    if (superblock.freeInodes == 0) return 0; // Inodes full
    
    for (size_t i = 0; i < inodeBitmap.size(); ++i) {
        if (inodeBitmap[i] != 0xFF) {
            for (int bit = 0; bit < 8; ++bit) {
                if ((inodeBitmap[i] & (1 << bit)) == 0) {
                    inodeBitmap[i] |= (1 << bit);
                    superblock.freeInodes--;
                    writeSuperblock();
                    return i * 8 + bit;
                }
            }
        }
    }
    return 0;
}

void VirtualDisk::freeInode(uint32_t inodeNum) {
    if (inodeNum >= superblock.totalInodes) return;
    
    size_t byteIdx = inodeNum / 8;
    int bitIdx = inodeNum % 8;
    
    if (inodeBitmap[byteIdx] & (1 << bitIdx)) {
        inodeBitmap[byteIdx] &= ~(1 << bitIdx);
        superblock.freeInodes++;
        writeSuperblock();
    }
}
