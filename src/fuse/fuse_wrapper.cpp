#define FUSE_USE_VERSION 31

#ifdef __linux__
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include "svf/vfs/FileSystem.h"

// Global pointer to our SVF file system instance
static FileSystem* svf_instance = nullptr;

static int svf_getattr(const char *path, struct stat *stbuf) {
    int res = 0;
    memset(stbuf, 0, sizeof(struct stat));
    
    // In a real implementation, we would query svf_instance->stat(path)
    // For this mockup, we check if it's the root directory
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        // Query our file system
        // Mocking behavior since FileSystem doesn't expose stat() yet
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = 4096; // Dummy size
    }
    
    return res;
}

static int svf_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi) {
    (void) offset;
    (void) fi;
    
    // Standard FUSE directory entries
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    
    // Ideally, we'd loop over svf_instance->listDirectory(path)
    // and call filler() for each file
    
    return 0;
}

static int svf_open(const char *path, struct fuse_file_info *fi) {
    // Forward open to SVF
    // int fd = svf_instance->openFile(path, 3);
    // if (fd < 0) return -ENOENT;
    // fi->fh = fd;
    return 0;
}

static int svf_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    // Forward read to SVF
    // std::string content = svf_instance->readFile(fi->fh);
    // copy content to buf based on offset and size
    return size;
}

static int svf_write(const char *path, const char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    // Forward write to SVF
    // std::string content(buf, size);
    // svf_instance->writeFile(fi->fh, content);
    return size;
}

static struct fuse_operations svf_oper = {
    .getattr = svf_getattr,
    .open    = svf_open,
    .read    = svf_read,
    .write   = svf_write,
    .readdir = svf_readdir,
};

int start_fuse_server(int argc, char *argv[], FileSystem* fs) {
    svf_instance = fs;
    return fuse_main(argc, argv, &svf_oper, NULL);
}

#else
// Windows/Non-Linux stub
#include <iostream>
#include "svf/vfs/FileSystem.h"

int start_fuse_server(int argc, char *argv[], FileSystem* fs) {
    std::cerr << "FUSE binding is only supported on Linux via libfuse.\n";
    std::cerr << "Compile this project on Ubuntu/Debian and pass mount point as argument.\n";
    return 1;
}
#endif
