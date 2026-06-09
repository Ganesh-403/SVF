#include "svf/storage/BTree.h"
#include "svf/vfs/Inode.h"
#include <iostream>
#include <cstring>
#include <cstdio>

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
    size_t totalBytes = (size_t)superblock.totalBlocks * (size_t)superblock.blockSize;
    std::cout << "[DISK] createEmptyDisk totalBytes=" << totalBytes << "\n";
    std::cout.flush();
    if (totalBytes == 0) totalBytes = 1;
    newDisk.seekp((std::streamoff)totalBytes - 1);
    newDisk.put('\0');
    newDisk.close();
}

void VirtualDisk::format() {
    createEmptyDisk();
    
    // Reset internal state
    superblock = Superblock(); 
    superblock.freeInodes = superblock.totalInodes;
    superblock.freeBlocks = superblock.totalBlocks;

    inodeBitmap.assign((superblock.totalInodes + 7) / 8, 0);
    dataBitmap.assign((superblock.totalBlocks + 7) / 8, 0);

    // Reserve system blocks
    for(uint32_t i = 0; i < superblock.dataStartBlock; i++) {
        dataBitmap[i / 8] |= (1 << (i % 8));
        superblock.freeBlocks--;
    }

    // Reserve Inode 0 (Sentinel) and 1 (Root)
    inodeBitmap[0] |= (1 << 0);
    inodeBitmap[0] |= (1 << 1);
    superblock.freeInodes -= 2;

    diskFile.open(diskFilePath, std::ios::in | std::ios::out | std::ios::binary);
    if (diskFile.is_open()) {
        diskFile.seekg(0, std::ios::end);
        std::cout << "[DISK] format: diskFile size after open=" << diskFile.tellg() << "\n";
        std::cout.flush();
        diskFile.seekg(0, std::ios::beg);
    }
    writeSuperblock();
    writeBitmaps();

    // Zero out Inode Table
    char zero[4096] = {0};
    for(uint32_t i = 0; i < 32; ++i) {
        writeBlock(superblock.inodeTableBlock + i, zero);
    }

    // Initialize Root Inode
    DiskInode root;
    std::memset(&root, 0, sizeof(DiskInode));
    root.id = 1;
    root.fileType = 2; // DIRECTORY
    root.mode = 0755;
    std::strncpy(root.owner, "admin", 31);
    root.directBlocks[0] = superblock.rootDirectoryBlock;
    writeInode(1, root);

    // Initialize Root Directory Block as a valid empty B-Tree leaf node
    BTreeNode rootNode;
    std::memset(&rootNode, 0, sizeof(BTreeNode));
    rootNode.blockId = superblock.rootDirectoryBlock;
    rootNode.isLeaf = true;
    rootNode.numKeys = 0;
    char btreeBuffer[4096] = {0};
    std::memcpy(btreeBuffer, &rootNode, sizeof(BTreeNode));
    writeBlock(superblock.rootDirectoryBlock, btreeBuffer);

    std::cout << "Virtual Disk Formatted Successfully.\n";
}

bool VirtualDisk::mount() {
    diskFile.open(diskFilePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!diskFile.is_open()) {
        std::cout << "Disk image not found. Creating and formatting new disk...\n";
        format();
        return true;
    }

    // Read and Validate Superblock
    diskFile.clear();  // Clear error flags before first operation
    diskFile.seekg(0, std::ios::beg);
    char buffer[sizeof(Superblock)];
    diskFile.read(buffer, sizeof(Superblock));
    
    if (diskFile.gcount() != (std::streamsize)sizeof(Superblock)) {
        std::cerr << "ERROR: Failed to read complete superblock. Read " 
                  << diskFile.gcount() << " bytes, expected " 
                  << sizeof(Superblock) << "\n";
        diskFile.close();
        format();
        return false;
    }
    
    std::memcpy(&superblock, buffer, sizeof(Superblock));

    if (superblock.magic != 0x53564633) {
        std::cout << "Invalid or outdated disk format. Re-formatting...\n";
        diskFile.close();
        format();
        return true;
    }

    // Load Bitmaps
    inodeBitmap.assign((superblock.totalInodes + 7) / 8, 0);
    diskFile.clear();  // Clear before seeking
    diskFile.seekg((uint64_t)superblock.inodeBitmapBlock * superblock.blockSize, std::ios::beg);
    diskFile.read(reinterpret_cast<char*>(inodeBitmap.data()), inodeBitmap.size());
    
    if (!diskFile) {
        std::cerr << "ERROR: Failed to read inode bitmap\n";
        return false;
    }

    dataBitmap.assign((superblock.totalBlocks + 7) / 8, 0);
    diskFile.clear();  // Clear before seeking
    diskFile.seekg((uint64_t)superblock.dataBitmapBlock * superblock.blockSize, std::ios::beg);
    diskFile.read(reinterpret_cast<char*>(dataBitmap.data()), dataBitmap.size());
    
    if (!diskFile) {
        std::cerr << "ERROR: Failed to read data bitmap\n";
        return false;
    }

    std::cout << "Virtual Disk Mounted Successfully. Free Blocks: " << superblock.freeBlocks << "\n";
    return true;
}

void VirtualDisk::writeSuperblock() {
    diskFile.clear();  // Clear any error flags from previous operations
    diskFile.seekp(0, std::ios::beg);  // Explicit ios::beg for Windows compatibility
    diskFile.write(reinterpret_cast<const char*>(&superblock), sizeof(Superblock));
    diskFile.flush();  // Ensure write completes
    
    if (!diskFile) {
        std::cerr << "ERROR: Failed to write superblock to disk\n";
    }
}

void VirtualDisk::writeBitmaps() {
    writeBlock(superblock.inodeBitmapBlock, reinterpret_cast<const char*>(inodeBitmap.data()));
    writeBlock(superblock.dataBitmapBlock, reinterpret_cast<const char*>(dataBitmap.data()));
}

bool VirtualDisk::readBlock(uint32_t blockNum, char* buffer) {
    if (blockNum >= superblock.totalBlocks) return false;
    uint64_t offset = (uint64_t)blockNum * (uint64_t)superblock.blockSize;

    if (diskFile.is_open()) {
        // Use existing fstream handle to avoid Windows sharing violations
        diskFile.clear();
        // get file size for diagnostics
        diskFile.seekg(0, std::ios::end);
        std::streampos fileSize = diskFile.tellg();
        std::cout << "[DISK] readBlock (fstream) fileSize=" << fileSize << "\n";
        std::cout.flush();

        diskFile.seekg((std::streamoff)offset, std::ios::beg);
        std::cout << "[DISK] readBlock: after seekg good=" << diskFile.good() << " eof=" << diskFile.eof() << " fail=" << diskFile.fail() << " bad=" << diskFile.bad() << "\n";
        std::cout.flush();
        if (!diskFile) {
            std::cerr << "[DISK] readBlock: seekg failed for block " << blockNum << "\n";
            std::fflush(stderr);
            return false;
        }

        diskFile.read(buffer, superblock.blockSize);
        std::cout << "[DISK] readBlock: after read good=" << diskFile.good() << " eof=" << diskFile.eof() << " fail=" << diskFile.fail() << " bad=" << diskFile.bad() << "\n";
        std::cout.flush();
        std::streamsize readBytes = diskFile.gcount();
        if (readBytes < 0) readBytes = 0;

        std::cout << "[DISK] readBlock (fstream) block=" << blockNum << " offset=" << offset << " readBytes=" << readBytes << "\n";
        std::cout.flush();

        if ((size_t)readBytes < superblock.blockSize) {
            std::memset(buffer + readBytes, 0, superblock.blockSize - (size_t)readBytes);
        }

        size_t dumpLen = std::min<size_t>(16, (size_t)readBytes);
        if (dumpLen > 0) {
            std::cout << "[DISK] readBlock first16:";
            for (size_t i = 0; i < dumpLen; ++i) {
                unsigned char c = static_cast<unsigned char>(buffer[i]);
                std::printf(" %02X", c);
            }
            std::cout << "\n";
            std::cout.flush();
        }

        return true;
    }

    // Fallback to stdio when fstream is not available
    FILE* f = fopen(diskFilePath.c_str(), "rb");
    if (!f) {
        std::cerr << "[DISK] readBlock: fopen failed for " << diskFilePath << "\n";
        std::fflush(stderr);
        return false;
    }

#ifdef _WIN32
    if (_fseeki64(f, (long long)offset, SEEK_SET) != 0) {
#else
    if (fseek(f, (long)offset, SEEK_SET) != 0) {
#endif
        std::cerr << "[DISK] readBlock: fseek failed for block " << blockNum << " offset " << offset << "\n";
        std::fflush(stderr);
        fclose(f);
        return false;
    }

    size_t readBytes = fread(buffer, 1, superblock.blockSize, f);
    int ferr = ferror(f);
    if (ferr) {
        std::cerr << "[DISK] readBlock: fread reported error (ferror=" << ferr << ") for block " << blockNum << "\n";
        std::fflush(stderr);
    }

    std::cout << "[DISK] readBlock block=" << blockNum << " offset=" << offset << " readBytes=" << readBytes << "\n";
    std::cout.flush();

    if (readBytes < superblock.blockSize) {
        std::memset(buffer + readBytes, 0, superblock.blockSize - readBytes);
    }

    // Print first 16 bytes for quick inspection
    size_t dumpLen = std::min<size_t>(16, readBytes);
    if (dumpLen > 0) {
        std::cout << "[DISK] readBlock first16:";
        for (size_t i = 0; i < dumpLen; ++i) {
            unsigned char c = static_cast<unsigned char>(buffer[i]);
            std::printf(" %02X", c);
        }
        std::cout << "\n";
        std::cout.flush();
    }

    fclose(f);
    return true;
}

bool VirtualDisk::writeBlock(uint32_t blockNum, const char* buffer) {
    if (blockNum >= superblock.totalBlocks) return false;
    uint64_t offset = (uint64_t)blockNum * (uint64_t)superblock.blockSize;

    if (diskFile.is_open()) {
        diskFile.clear();
        diskFile.seekp((std::streamoff)offset, std::ios::beg);
        if (!diskFile) {
            std::cerr << "[DISK] writeBlock: seekp failed for block " << blockNum << "\n";
            std::fflush(stderr);
            return false;
        }

        diskFile.write(buffer, superblock.blockSize);
        diskFile.flush();
        return (bool)diskFile;
    }

    FILE* f = fopen(diskFilePath.c_str(), "rb+");
    if (!f) {
        // try create
        f = fopen(diskFilePath.c_str(), "wb+");
        if (!f) return false;
    }

#ifdef _WIN32
    if (_fseeki64(f, (long long)offset, SEEK_SET) != 0) {
#else
    if (fseek(f, (long)offset, SEEK_SET) != 0) {
#endif
        fclose(f);
        return false;
    }

    size_t written = fwrite(buffer, 1, superblock.blockSize, f);
    fflush(f);
    fclose(f);
    return (written == superblock.blockSize);
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

bool VirtualDisk::readInode(uint32_t inodeNum, DiskInode& inode) {
    if (inodeNum >= superblock.totalInodes) return false;
    
    uint32_t offsetInTable = inodeNum * 112; // sizeof(DiskInode) is 112
    uint32_t blockIdx = superblock.inodeTableBlock + (offsetInTable / superblock.blockSize);
    uint32_t offsetInBlock = offsetInTable % superblock.blockSize;
    
    char buffer[4096];
    if (!readBlock(blockIdx, buffer)) return false;
    
    std::memcpy(&inode, buffer + offsetInBlock, 112);
    return true;
}

bool VirtualDisk::writeInode(uint32_t inodeNum, const DiskInode& inode) {
    if (inodeNum >= superblock.totalInodes) return false;
    
    uint32_t offsetInTable = inodeNum * 112;
    uint32_t blockIdx = superblock.inodeTableBlock + (offsetInTable / superblock.blockSize);
    uint32_t offsetInBlock = offsetInTable % superblock.blockSize;
    
    char buffer[4096];
    if (!readBlock(blockIdx, buffer)) return false;
    
    std::memcpy(buffer + offsetInBlock, &inode, 112);
    return writeBlock(blockIdx, buffer);
}
