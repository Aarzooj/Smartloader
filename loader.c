#include "loader.h"

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;

#define PAGE_SIZE 4096

// void signal_handler(int signum)
// {
//   sleep(1);
//   printf("SIGSEGV received\n");
// }

void signal_handler(int signo, siginfo_t *si, void *context)
{
  sleep(1);
  printf("Segmentation fault (Page Fault) at address: %p\n", si->si_addr);
  uint32_t fault_address = (uint32_t)si->si_addr;

  // Align the fault address to the nearest page boundary
  uint32_t page_base = fault_address & ~(PAGE_SIZE - 1);
  printf("Page base: %p\n", (void *)page_base);
  void *allocated_page = mmap((void *)page_base, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  printf("Allocated at address: %p\n", allocated_page);
  printf("Size of segment: %d\n", PAGE_SIZE);
  // You can try to analyze or log additional information here if needed.
  // mprotect(allocated_page, page_base, PROT_READ | PROT_EXEC);
  // exit(1);
  for (int i = 0; i < ehdr->e_phnum; i++)
  {
    Elf32_Phdr *ph = &phdr[i];
    if (ph->p_type == PT_LOAD)
    {
      void *segment_address = (void *)(page_base + ph->p_vaddr);
      // Copy segment data from ELF file into allocated_page
      memcpy(allocated_page, (void *)((uintptr_t)ehdr + ph->p_offset), ph->p_filesz);
      // Adjust memory protection
      mprotect(allocated_page, PAGE_SIZE, PROT_READ | PROT_EXEC);
    }
  }
}

void loader_cleanup()
{
  ehdr = NULL;
  free(ehdr);
  phdr = NULL;
  free(phdr);
}

void load_and_run_elf(char **exe)
{
  fd = open(*exe, O_RDONLY);

  off_t fd_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);

  char *heap_mem;
  heap_mem = (char *)malloc(fd_size);

  if (!heap_mem)
  {
    perror("Error: Memory allocation failed");
    exit(1);
  }

  ssize_t file_read = read(fd, heap_mem, fd_size);

  if (file_read < 0 || (size_t)file_read != fd_size)
  {
    perror("Error: File read operation failed");
    free(heap_mem);
    exit(1);
  }

  ehdr = (Elf32_Ehdr *)heap_mem;

  if (ehdr->e_type != ET_EXEC)
  {
    printf("Unsupported elf file");
    exit(1);
  }

  phdr = (Elf32_Phdr *)(heap_mem + ehdr->e_phoff);

  unsigned int entry = ehdr->e_entry;

  Elf32_Phdr *tmp = phdr;
  int total_phdr = ehdr->e_phnum;
  void *virtual_mem;
  void *entry_addr = (void *)entry;
  int i = 0;

  for (int i = 0; i < ehdr->e_phnum; i++)
  {
    Elf32_Phdr *ph = &phdr[i];
    if (ph->p_type == PT_LOAD)
    {
      void *segment_address = (void *)(ehdr->e_entry + ph->p_vaddr);
      mprotect(segment_address, ph->p_memsz, PROT_READ | PROT_EXEC);
    }
  }
  if (entry_addr != NULL)
  {
    int (*_start)(void) = (int (*)(void))entry_addr;

    int result = _start();
    printf("User _start return value = %d\n", result);
  }
  else
  {
    printf("Entry Point Address is out of bounds.\n");
    free(heap_mem);
    exit(1);
  }
  close(fd);
}

int main(int argc, char **argv)
{
  if (argc != 2)
  {
    printf("Usage: %s <ELF Executable> \n", argv[0]);
    exit(1);
  }
  FILE *elfFile = fopen(argv[1], "rb");
  if (!elfFile)
  {
    printf("Error: Unable to open ELF file.\n");
    exit(1);
  }
  fclose(elfFile);

  // signal(SIGSEGV, signal_handler);
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = signal_handler;

  if (sigaction(SIGSEGV, &sa, NULL) == -1)
  {
    perror("sigaction");
    exit(2);
  }
  load_and_run_elf(&argv[1]);

  loader_cleanup();

  return 0;
}