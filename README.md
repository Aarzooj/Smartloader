# A4Smartloader

- The contents of ELF file are first loaded into the heap memory.
- The PT_LOAD segments containing all sections are stored in an array.
- Entrypoint address is run directly which generates a `segmentation fault`. `SIGSEGV` handler is invoked.
- It iterates through all the loaded PT_LOAD segments from the heap memory. When the segment containing the fault address is found, a page of size 4096 is loaded using `mmap` and the program resumes execution.
- This process is repeated until the submitted program stops execution.