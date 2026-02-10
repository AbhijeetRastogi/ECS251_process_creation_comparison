#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <spawn.h>
#include <string.h>
#include <stdint.h> 

extern char **environ;

#define TEST_MEMORY_MB 100
#define PAGE_SIZE 4096

void test_fork() {
    printf("\n=== Testing fork() ===\n");
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed");
        return;
    }
    
    if (pid == 0) {
        printf("  Child process (PID: %d)\n", getpid());
        _exit(0);
    } else {
        printf("  Parent process (PID: %d), child PID: %d\n", getpid(), pid);
        int status;
        waitpid(pid, &status, 0);
        printf("  Child exited with status: %d\n", WEXITSTATUS(status));
    }
}

void test_vfork() {
    printf("\n=== Testing vfork() ===\n");
    
    pid_t pid = vfork();
    if (pid < 0) {
        perror("vfork failed");
        return;
    }
    
    if (pid == 0) {
        _exit(0);
    } else {
        printf("  Parent process (PID: %d), child completed\n", getpid());
        int status;
        waitpid(pid, &status, 0);
        printf("  Child exited with status: %d\n", WEXITSTATUS(status));
    }
}

void test_posix_spawn() {
    printf("\n=== Testing posix_spawn() ===\n");
    
    char *argv[] = {"/bin/true", NULL};
    pid_t pid;
    
    int ret = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ);
    if (ret != 0) {
        fprintf(stderr, "posix_spawn failed: %s\n", strerror(ret));
        return;
    }
    
    printf("  Spawned process PID: %d\n", pid);
    int status;
    waitpid(pid, &status, 0);
    printf("  Child exited with status: %d\n", WEXITSTATUS(status));
}

void test_memory_allocation() {
    printf("\n=== Testing memory allocation ===\n");
    
    size_t mem_size = TEST_MEMORY_MB * 1024ULL * 1024ULL;
    printf("  Allocating %d MB...\n", TEST_MEMORY_MB);
    
    void *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("  mmap failed");
        return;
    }
    
    printf("  Memory allocated at: %p\n", mem);
    
    // Touch pages
    printf("  Touching pages...\n");
    size_t num_pages = mem_size / PAGE_SIZE;
    for (size_t i = 0; i < num_pages; i++) {
        ((char*)mem)[i * PAGE_SIZE] = 1;
    }
    
    printf("  Touched %zu pages\n", num_pages);
    
    munmap(mem, mem_size);
    printf("  Memory freed\n");
}

void test_huge_pages() {
    printf("\n=== Testing huge pages ===\n");
    
    size_t mem_size = TEST_MEMORY_MB * 1024ULL * 1024ULL;
    
    void *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    if (mem == MAP_FAILED) {
        perror("  mmap failed");
        return;
    }
    
    // Try to use huge pages
    if (madvise(mem, mem_size, MADV_HUGEPAGE) != 0) {
        perror("  madvise MADV_HUGEPAGE failed (this is okay if THP is disabled)");
    } else {
        printf("  madvise MADV_HUGEPAGE succeeded\n");
    }
    
    // Touch pages
    for (size_t i = 0; i < mem_size; i += PAGE_SIZE) {
        ((char*)mem)[i] = 1;
    }
    
    printf("  Memory touched with THP hint\n");
    
    munmap(mem, mem_size);
}

void test_timing() {
    printf("\n=== Testing high-resolution timing ===\n");
    
    struct timespec ts;
    if (clock_getres(CLOCK_MONOTONIC, &ts) == 0) {
        printf("  CLOCK_MONOTONIC resolution: %ld.%09ld seconds\n", 
               ts.tv_sec, ts.tv_nsec);
    }
    
    // Test actual timing
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t start = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    
    // Do something quick
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t end = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    
    printf("  Sample timing measurement: %lu nanoseconds\n", end - start);
}

int main() {
    printf("========================================\n");
    printf("Process Creation Benchmark - Quick Test\n");
    printf("========================================\n");
    
    test_fork();
    test_vfork();
    test_posix_spawn();
    test_memory_allocation();
    test_huge_pages();
    test_timing();
    
    printf("\n========================================\n");
    printf("All tests completed!\n");
    printf("========================================\n");
    
    return 0;
}
