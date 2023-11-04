#include <stdio.h>
#include <elf.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <signal.h>

#define PAGE_SIZE 4096
#define MAX_PAGES 10

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)
#define ROUND_UP(a, b) (((a + (b - 1)) & -b))

#define lli long long int

struct sigaction old_state;

typedef struct
{
    uintptr_t vaddr;
    size_t mem_size;
    off_t offset;
    int perm;
    int file_size;
    int data[MAX_PAGES];
} Segment;

void load_page_data(Segment *segment, char *exec_path, char *page, uintptr_t addr);
void segv_handler(int signum, siginfo_t *info, void *context);
void load_and_run_elf(char** exe);
void initialise_signal();
void loader_cleanup();