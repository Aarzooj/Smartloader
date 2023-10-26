#include "loader.h"

Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd;

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
}

/*
 * Load and run the ELF executable file
 */
void load_and_run_elf(char **exe)
{
  // 1. Load entire binary content into the memory from the ELF file.
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

  // elf header
  ehdr = (Elf32_Ehdr *)heap_mem;

  // checking if the file type can be handled by the loader
  if (ehdr->e_type != ET_EXEC)
  {
    printf("Unsupported elf file");
    exit(1);
  }

  // program header
  phdr = (Elf32_Phdr *)(heap_mem + ehdr->e_phoff);

  // entrypoint address in elf header
  unsigned int entry = ehdr->e_entry;

  Elf32_Phdr *tmp = phdr;
  int total_phdr = ehdr->e_phnum;
  void *virtual_mem;
  void *entry_addr;
  int i = 0;

  // 2. Iterate through the PHDR table and find the section of PT_LOAD
  //    type that contains the address of the entrypoint method in fib.c
  while (i < total_phdr)
  {
    if (tmp->p_type == PT_LOAD)
    {
      // 3. Allocate memory of the size "p_memsz" using mmap function
      //    and then copy the segment content
      virtual_mem = mmap(NULL, tmp->p_memsz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
      memcpy(virtual_mem, heap_mem + tmp->p_offset, tmp->p_memsz);

      // verifying if memory mapping was successful
      if (virtual_mem == MAP_FAILED)
      {
        perror("Error: Memory mapping failed");
        exit(1);
      }

      // 4. Navigate to the entrypoint address into the segment loaded in the memory in above step
      entry_addr = virtual_mem + (entry - tmp->p_vaddr);

      // checking if the entry point address lies within the boundaries of virtual memory
      if (entry_addr >= virtual_mem && entry_addr <= (virtual_mem + tmp->p_offset))
      {
        break;
      }
    }
    i++;
    tmp++;
  }

  if (entry_addr != NULL)
  {
    // 5. Typecast the address to that of function pointer matching "_start" method in fib.c.
    int (*_start)(void) = (int (*)(void))entry_addr;

    // 6. Call the "_start" method and print the value returned from the "_start"
    int result = _start();
    printf("User _start return value = %d\n", result);
  }
  else
  {
    // error handling if the entry point is out of bounds
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
  // 1. carry out necessary checks on the input ELF file

  // checking if ELF file exists in the provided path
  FILE *elfFile = fopen(argv[1], "rb");
  if (!elfFile)
  {
    printf("Error: Unable to open ELF file.\n");
    exit(1);
  }
  fclose(elfFile);

  // 2. passing it to the loader for carrying out the loading/execution
  load_and_run_elf(&argv[1]);

  // 3. invoke the cleanup routine inside the loader
  loader_cleanup();

  return 0;
}