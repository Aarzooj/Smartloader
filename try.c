#include "try.h"
#include <signal.h>

#define MAX(a, b) (a > b ? a : b)
#define MIN(a, b) (a < b ? a : b)
#define lli long long int

char *exec_path;
uintptr_t base_addr;

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;

int page_fault = 0;
int page_allocations = 0;
lli fragmentation = 0;

int entry;
int num_load_phdr = 0;

typedef struct
{
    uintptr_t vaddr;
    size_t mem_size;
    off_t offset;
    int perm;
    int file_size;
    int data[MAX_PAGES];
} Segment;

Segment *segments;

void load_page_data(Segment *segment, char *exec_path, char *page, uintptr_t addr)
{
    int num_page = (addr - segment->vaddr) / PAGE_SIZE;
    int exec_fd = open(exec_path, O_RDONLY);
    lseek(exec_fd, segment->offset + num_page * PAGE_SIZE, SEEK_SET);
    char *temp = (char *)malloc(PAGE_SIZE * sizeof(char));
    int rd = read(exec_fd, temp, MIN(PAGE_SIZE, MAX(0, segment->file_size - num_page * PAGE_SIZE)));
    memcpy(page, temp, rd);
    close(exec_fd);
    free(temp);
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
    if (info->si_code == SEGV_ACCERR)
    {
        printf("Permission Denied: ");
        old_state.sa_sigaction(signum, info, context);
    }
    void *fault_addr = info->si_addr;
    Segment *segment;
    int found = 0;
    for (int i = 0; i < num_load_phdr; i++)
    {
        if (fault_addr >= (void *)segments[i].vaddr && fault_addr < (void *)(segments[i].vaddr + segments[i].mem_size))
        {
            segment = &segments[i];
            found = 1;
            break;
        }
    }
    if (found == 0)
    {
        printf("Memory out of bounds: ");
        old_state.sa_sigaction(signum, info, context);
    }
    int offset = (uintptr_t)info->si_addr - segment->vaddr;
    int current_page = offset / PAGE_SIZE;
    int pg = segment->data[current_page];
    if (pg != 0)
    {
        printf("Fault in submitted code: ");
        old_state.sa_sigaction(signum, info, context);
    }
    page_fault++;
    void *page = mmap((void *)segment->vaddr + current_page * PAGE_SIZE, PAGE_SIZE, PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    page_allocations++;
    load_page_data(segment, exec_path, page, (uintptr_t)info->si_addr);
    mprotect(page, PAGE_SIZE, segment->perm);
    segment->data[current_page] = 1;
}

void load_and_run_elf(char **exe)
{
    fd = open(*exe, O_RDONLY);

    off_t fd_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    char *heap_mem;
    heap_mem = (char *)malloc(fd_size);

    // verifying if memory is allocated
    if (!heap_mem)
    {
        perror("Error: Memory allocation failed");
        exit(1);
    }

    ssize_t file_read = read(fd, heap_mem, fd_size);

    // verifying if file is read successfully
    if (file_read < 0 || (size_t)file_read != fd_size)
    {
        perror("Error: File read operation failed");
        free(heap_mem);
        exit(1);
    }
    ehdr = (Elf32_Ehdr *)heap_mem;
    phdr = (Elf32_Phdr *)(heap_mem + ehdr->e_phoff);
    Elf32_Phdr *tmp = phdr;
    int total_phdr = ehdr->e_phnum;
    int i = 0;
    while (i < total_phdr)
    {
        if (tmp->p_type == PT_LOAD)
        {
            num_load_phdr++;
        }
        i++;
        tmp++;
    }
    base_addr = 0xffffffff;
    entry = ehdr->e_entry;
    segments = (Segment *)malloc(num_load_phdr * sizeof(Segment));
    int j = 0;
    for (int i = 0; i < total_phdr; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            Segment *seg = &segments[j];
            seg->perm = 0;
            if (phdr[i].p_flags & PF_X)
                seg->perm |= 4;
            if (phdr[i].p_flags & PF_R)
                seg->perm |= 1;
            if (phdr[i].p_flags & PF_W)
                seg->perm |= 2;
            seg->vaddr = (((phdr[i].p_vaddr) + ((PAGE_SIZE)-1)) & -PAGE_SIZE);
            seg->offset = phdr[i].p_offset - (phdr[i].p_vaddr - seg->vaddr);
            seg->mem_size = phdr[i].p_memsz + (phdr[i].p_vaddr - seg->vaddr);
            seg->file_size = phdr[i].p_filesz + (phdr[i].p_vaddr - seg->vaddr);
            memset(seg[i].data, 0, MAX_PAGES * sizeof(int));
            int num_pages = (seg->mem_size % PAGE_SIZE == 0) ? (seg->mem_size / PAGE_SIZE) : (seg->mem_size / PAGE_SIZE) + 1;
            lli fragment = num_pages * PAGE_SIZE - seg->mem_size;
            fragmentation += fragment;
            if (seg->vaddr < base_addr)
                base_addr = seg->vaddr;
            j++;
        }
    }
    int (*_start)(void) = (int (*)(void))entry;
    int result = _start();
    printf("User _start return value = %d\n", result);
    printf("Page faults: %d\n", page_fault);
    printf("Page Allocations: %d\n", page_fault);
    printf("Total internal fragmentations: %f KB\n", (double)fragmentation / PAGE_SIZE);
}

void initialise_signal()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, &old_state) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <ELF Executable> \n", argv[0]);
        exit(1);
    }
    exec_path = argv[1];
    FILE *elfFile = fopen(argv[1], "rb");
    if (!elfFile)
    {
        printf("Error: Unable to open ELF file.\n");
        exit(1);
    }
    fclose(elfFile);
    initialise_signal();
    load_and_run_elf(&argv[1]);
    return 0;
}