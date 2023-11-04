#include "try.h"

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

Segment *segments;

/*
 * release memory and other cleanups
 */
void loader_cleanup()
{
  // freeing the memory for globally defined variables
  ehdr = NULL;
  free(ehdr);
  phdr = NULL;
  free(phdr);
  free(segments);
  exec_path = NULL;
  free(exec_path);
}

// Reading the elf file to store the data in the page
void load_page_data(Segment *segment, char *exec_path, char *page, uintptr_t addr)
{
    int num_page = (addr - segment->vaddr) / PAGE_SIZE;
    int exec_fd = open(exec_path, O_RDONLY);
    lseek(exec_fd, segment->offset + num_page * PAGE_SIZE, SEEK_SET);
    char *temp = (char *)malloc(PAGE_SIZE * sizeof(char));
    if (temp == NULL)
    {
        perror("Can't allocate memory\n");
        exit(EXIT_FAILURE);
    }
    int rd = read(exec_fd, temp, MIN(PAGE_SIZE, MAX(0, segment->file_size - num_page * PAGE_SIZE)));
    memcpy(page, temp, rd);
    close(exec_fd);
    free(temp);
}

// Segmentation fault handler
void segv_handler(int signum, siginfo_t *info, void *context)
{
    // if permission to access is denied, then the original action of SIGSEGV signal is invoked
    if (info->si_code == SEGV_ACCERR)
    {
        printf("Permission Denied: ");
        old_state.sa_sigaction(signum, info, context);
    }
    void *fault_addr = info->si_addr;
    Segment *segment;
    int found = 0;
    // iterating through the loaded segments to check the bounds for required address
    for (int i = 0; i < num_load_phdr; i++)
    {
        if (fault_addr >= (void *)segments[i].vaddr && fault_addr < (void *)(segments[i].vaddr + segments[i].mem_size))
        {
            segment = &segments[i];
            found = 1;
            break;
        }
    }
    // address not found, restores the default action for SIGSEGV signal
    if (found == 0)
    {
        printf("Memory out of bounds: ");
        old_state.sa_sigaction(signum, info, context);
    }
    // Calculating the offset of the fault address
    int offset = (uintptr_t)info->si_addr - segment->vaddr;
    // Page containing the fault address in the segment
    int current_page = offset / PAGE_SIZE;
    int pg = segment->data[current_page];
    // pg = 1 which means the page is found
    // signifies SIGSEGV signal is raised due to segmentation fault in the page code, not page fault
    if (pg != 0)
    {
        printf("Fault in submitted code: ");
        old_state.sa_sigaction(signum, info, context);
    }
    page_fault++;
    // Mapping the page to access it
    void *page = mmap((void *)segment->vaddr + current_page * PAGE_SIZE, PAGE_SIZE, PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        perror("Error in mapping\n");
        exit(EXIT_FAILURE);
    }
    page_allocations++;
    // Reading the elf file again to store data in the mapped address
    load_page_data(segment, exec_path, page, (uintptr_t)info->si_addr);
    // setting the read, write, execute permissions of the page according to the permissions of the respective segment
    mprotect(page, PAGE_SIZE, segment->perm);
    // Page added in the array
    segment->data[current_page] = 1;
}

// Running the elf file and loading the segments to the heap
void load_and_run_elf(char **exe)
{
    fd = open(*exe, O_RDONLY);
    if (fd == -1)
    {
        perror("Can't open file\n");
        exit(EXIT_FAILURE);
    }

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
    entry = ehdr->e_entry;
    // array storing PT_LOAD segments, which contain sections of the code
    segments = (Segment *)malloc(num_load_phdr * sizeof(Segment));
    int j = 0;
    for (int i = 0; i < total_phdr; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
        {
            Segment *seg = &segments[j];
            seg->perm = 0;
            // Setting read, write and execute permissions for the loaded segment
            if (phdr[i].p_flags & PF_X)
            {
                seg->perm |= 4;
            }
            if (phdr[i].p_flags & PF_R)
            {
                seg->perm |= 1;
            }
            if (phdr[i].p_flags & PF_W)
            {
                seg->perm |= 2;
            }
            // Aligning the virtual addresses to the closest multiple of the PAGE_SIZE rounded up
            seg->vaddr = ROUND_UP(phdr[i].p_vaddr, PAGE_SIZE);
            // Setting the other parameters of the segment wrt to the program header
            seg->offset = phdr[i].p_offset - (phdr[i].p_vaddr - seg->vaddr);
            seg->mem_size = phdr[i].p_memsz + (phdr[i].p_vaddr - seg->vaddr);
            seg->file_size = phdr[i].p_filesz + (phdr[i].p_vaddr - seg->vaddr);
            // Initialising the page data array to 0
            memset(seg[i].data, 0, MAX_PAGES * sizeof(int));
            // Calculating the fragmentation of each loaded segment
            int allocated_memory = ROUND_UP(seg->mem_size, PAGE_SIZE);
            lli fragment = allocated_memory - seg->mem_size;
            fragmentation += fragment;
            j++;
        }
    }
    // directly running the code
    int (*_start)(void) = (int (*)(void))entry;
    int result = _start();
    printf("User _start return value = %d\n", result);
    printf("Page faults: %d\n", page_fault);
    printf("Page Allocations: %d\n", page_fault);
    printf("Total internal fragmentations: %f KB\n", (double)fragmentation / 1024);
}

// Initialising the SIGSEGV signal to set the handler as segv_handler
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

// main function
int main(int argc, char **argv)
{
    // check for command-line arguments
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
    loader_cleanup();
    return 0;
}