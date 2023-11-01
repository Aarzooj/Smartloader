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

struct sigaction old_state;

void load_and_run_elf(char** exe);
void loader_cleanup();