#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define HUGEPAGE_SIZE (32 * 1024 * 1024)
#define LOOP_COUNT 10
#define MAP_TEE_SHARED         0x200000

int main()
{
    const char *filepath = "/dev/hugepages/testfile";
    int fd;

    for (int i = 0; i < LOOP_COUNT; i++) {

        // 1. create hugepage-backed file under hugetlbfs mount
        fd = open(filepath, O_CREAT | O_RDWR, 0755);
        if (fd < 0) {
            perror("open");
            return 1;
        }

        // 2. set the file size to 2MB
        if (ftruncate(fd, HUGEPAGE_SIZE) != 0) {
            perror("ftruncate");
            close(fd);
            return 1;
        }

        // 3. mmap with MAP_SHARED + MAP_HUGETLB
        void *addr = mmap(NULL,
                          HUGEPAGE_SIZE,
                          PROT_READ | PROT_WRITE,
#if 0
                          MAP_SHARED | MAP_HUGETLB | MAP_TEE_SHARED,
                          fd,
#else
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_TEE_SHARED,
                          -1,
#endif
                          0);
        if (addr == MAP_FAILED) {
            perror("mmap");
            close(fd);
            return 1;
        }

        printf("Loop %d: mapped hugepage at %p\n", i, addr);

        // 4. memset the hugepage
        memset(addr, 0, HUGEPAGE_SIZE);

        // 5. unmap
        if (munmap(addr, HUGEPAGE_SIZE) != 0) {
            perror("munmap");
            close(fd);
            return 1;
        }

        close(fd);

        // Delete file so next iteration creates a new fresh hugepage
        unlink(filepath);
    }

    return 0;
}

