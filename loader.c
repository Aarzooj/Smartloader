#include "loader.h"
#include <signal.h>

char * exec_path;

#define ALIGN_DOWN(v, a) ((v) & ~((a)-1))
#define ALIGN_UP(v, a) (((v) + ((a)-1)) & ~((a)-1))

#define PERM_R 0x1
#define PERM_W 0x2
#define PERM_X 0x4

uintptr_t base_addr;
/* address of entry point */
uintptr_t entry;
/* number of segments */
int segments_no;
/* array of segments */

typedef struct page{
	unsigned int pg_num;
	struct page* next;
}page ;

typedef struct so_seg
{
    /* virtual address */
    uintptr_t vaddr;
    /* offset in file */
    unsigned int offset;
    /* size in memory (can be larger than file_size */
	unsigned int mem_size;
    /* permissions */
    unsigned int perm;
    /* custom data */
    void *data;
} so_seg_t;

so_seg_t *segments;

so_seg_t* find_segment_of_address(uintptr_t addr) {
	for (int i=0; i<segments_no; i++) {
		if (addr >= segments[i].vaddr && addr < segments[i].vaddr + segments[i].mem_size) {
			return &segments[i];
		}
	}
	return NULL;
}

void* find_page(page *linked_list, unsigned int pg_num) {
	while (linked_list != NULL) {
		if (linked_list->pg_num == pg_num) {
			return linked_list;
		}
		linked_list = linked_list->next;
	}
	return NULL;
} 


page* new_page(unsigned int pg_num) {
	page* aux = malloc(sizeof(page));
	aux->pg_num = pg_num;
	aux->next = NULL;
	return aux;
}

void insert_page(page *linked_list, unsigned int pg_num) {
	if (linked_list == NULL) {
		linked_list = new_page(pg_num);
	} else {
		while (linked_list->next == NULL) linked_list = linked_list -> next;
		
		linked_list -> next = new_page(pg_num);
	}
}
void copy_from_exec_to_page(so_seg_t *segment, char *exec_path, char *page, uintptr_t addr) {
	unsigned int num_page = (addr - segment->vaddr) / PAGE_SIZE;  // pata nhi
	int exec_fd = open(exec_path, O_RDONLY);
	lseek(exec_fd, segment->offset + num_page * PAGE_SIZE, SEEK_SET);
	char *buffer = calloc(PAGE_SIZE, sizeof(char));
	int rd = read(exec_fd, buffer, PAGE_SIZE);
	memcpy(page, buffer, rd);
	close(exec_fd);
	free(buffer);
}

static void segv_handler(int signum, siginfo_t *info, void *context){
	//printf("Hello ! Segmentation Fault\n");
    //exit(1);
    if (info->si_code == SEGV_ACCERR) {
		old_action.sa_sigaction(signum, info, context);
	}
	so_seg_t* segment = find_segment_of_address((uintptr_t)info->si_addr);
    // printf("%p\n",info->si_addr);
    // printf("%d\n",segment->vaddr);
    if (segment == NULL) {
		old_action.sa_sigaction(signum, info, context);
    }
    else{
        unsigned int offset_v_addr = (uintptr_t)info->si_addr - segment->vaddr;
		unsigned int current_page = offset_v_addr / PAGE_SIZE;
		page* pg = find_page(segment->data, current_page);
		if (pg != NULL) {
			old_action.sa_sigaction(signum, info, context);
		}
        void *page = mmap((void*)segment->vaddr + current_page * PAGE_SIZE, PAGE_SIZE, PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
		copy_from_exec_to_page(segment, exec_path, page, (uintptr_t)info->si_addr);
		mprotect(page, PAGE_SIZE, segment->perm);
		insert_page(segment->data, current_page);

    }
    // exit(1);
}

int so_init_loader(void)
{
    int rc;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO;
    rc = sigaction(SIGSEGV, &sa, &old_action);
    if (rc < 0)
    {
        perror("sigaction");
        return -1;
    }
    return 0;
}

void load_and_run_elf(char **exe)
{

    Elf32_Ehdr *ehdr;
    Elf32_Phdr *phdr;
    so_seg_t *seg;
    int fd;
    int num_load_phdr;
	int j;
    size_t diff;

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
    phdr = (Elf32_Phdr *)((intptr_t)ehdr + ehdr->e_phoff);

    num_load_phdr = 0;
    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_LOAD)
            num_load_phdr++;
    }

    base_addr = 0xffffffff;
	entry = ehdr->e_entry;
	segments_no = num_load_phdr;
	segments = (so_seg_t *)malloc(num_load_phdr * sizeof(so_seg_t));


    j = 0;
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			seg = &segments[j];

			seg->vaddr = ALIGN_DOWN(phdr[i].p_vaddr, PAGE_SIZE); // page_size check
			diff = phdr[i].p_vaddr - seg->vaddr;
			seg->offset = phdr[i].p_offset - diff;
            seg->mem_size = phdr[i].p_memsz + diff;
			seg->perm = 0;

			if (phdr[i].p_flags & PF_X)
				seg->perm |= PERM_X;
			if (phdr[i].p_flags & PF_R)
				seg->perm |= PERM_R;
			if (phdr[i].p_flags & PF_W)
				seg->perm |= PERM_W;

			if (seg->vaddr < base_addr)
				base_addr = seg->vaddr;

			j++;
		}
	}
    int (*_start)(void) = (int (*)(void))entry;
    int result = _start();
    printf("User _start return value = %d\n", result);

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
    so_init_loader();
    load_and_run_elf(&argv[1]);

    return 0;
}