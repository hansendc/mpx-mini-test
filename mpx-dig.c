#define _LARGEFILE64_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <fcntl.h>
#include "mpx-debug.h"
#include "mpx-mm.h"

unsigned long bounds_dir_global;

/*
 * Written by Dave Hansen <dave.hansen@intel.com>
 *
 * run like this:
 pid=31390; BDIR="$(cat /proc/$pid/smaps | grep -B1 2097152 | head -1 | awk -F- '{print $1}')"; ./mpx-dig $pid 0x$BDIR

NOTE:
 assumes that the only 2097152-kb VMA is the bounds dir
 */

long nr_incore(void *ptr, unsigned long size_bytes)
{
	int i;
	long ret = 0;
	long vec_len = size_bytes / PAGE_SIZE;
	unsigned char *vec = malloc(vec_len);
	//printf("vec size bytes: %ld\n", vec_len);
	if (!vec)
		abort();

	int incore_ret = mincore(ptr, size_bytes, vec);
	if (incore_ret) {
		printf("mincore ret: %d\n", incore_ret);
		perror("mincore");
		abort();
	}
	for (i = 0; i < vec_len; i++)
		ret += vec[i];
	free(vec);
	return ret;
}

char buf[100];
int open_proc(int pid, char *file)
{
	int fd;
	sprintf(&buf[0], "/proc/%d/%s", pid, file);
	fd = open(&buf[0], O_RDONLY);
	if (fd < 0) {
		perror(buf);
	}
	return fd;
}

void __dave_abort(int line)
{
	perror("abort");
	printf("abort @ %d\n", line);
	abort();
}
#define dave_abort() __dave_abort(__LINE__);

struct vaddr_range {
	unsigned long start;
	unsigned long end;
};
struct vaddr_range ranges[1000000];
int nr_ranges = 0;
int last_range = -1;


int pid_load_vaddrs(int pid)
{
	char *ret;
	int proc_maps_fd = open_proc(pid, "maps");
	char linebuf[10000];
	unsigned long start;
	unsigned long end;
	char rest[1000];

	FILE *f = fdopen(proc_maps_fd, "r");
	if (!f)
		dave_abort();
	while (!feof(f)) {
		ret = fgets(linebuf, sizeof(linebuf), f);
		if (ret == NULL) {
			if (feof(f))
				break;
			dave_abort();
		}

		int parsed = sscanf(linebuf, "%lx-%lx%s", &start, &end, rest);
		if (parsed != 3)
			dave_abort();

		//printf("result[%d]: %lx-%lx<->%s\n", parsed, start, end, rest);
		ranges[nr_ranges].start = start;
		ranges[nr_ranges].end = end;
		nr_ranges++;
		if (nr_ranges >= 1000000)
			dave_abort();
	}
	last_range = -1;
	fclose(f);
	close(proc_maps_fd);
	return 0;
}

static inline int vaddr_in_range(unsigned long vaddr, struct vaddr_range *r)
{
	if (vaddr < r->start)
		return 0;
	if (vaddr >= r->end)
		return 0;
	return 1;
}

static inline int vaddr_mapped_by_range(unsigned long vaddr)
{
	int i;

	if (last_range > 0 && vaddr_in_range(vaddr, &ranges[last_range]))
		return 1;

	for (i = 0; i < nr_ranges; i++) {
		struct vaddr_range *r = &ranges[i];
		if (vaddr_in_range(vaddr, r))
			continue;
		last_range = i;
		return 1;
	}
	return 0;
}

#define ADDRESS_SPACE_SIZE  (1UL<<48)
const unsigned long bounds_dir_size = 2 * (1UL << 30);
#define BOUNDS_DIR_NR_ENTRIES (bounds_dir_size / sizeof(unsigned long))
const unsigned long bt_size = 4 * (1UL << 20); // 4MB
const int bt_entry_size_bytes = sizeof(unsigned long) * 4;

void *read_bounds_table_into_buf(unsigned long table_vaddr)
{
#ifdef MPX_DIG_STANDALONE
	static char bt_buf[bt_size];
	off_t seek_ret = lseek(fd, table_vaddr, SEEK_SET);
	//printf("seeked to: %lx\n", seek_ret);
	if (seek_ret != table_vaddr)
		dave_abort();

	int read_ret = read(fd, &bt_buf, sizeof(bt_buf));
	//printf("%s() read: %d\n", __func__, read_ret);
	if (read_ret != sizeof(bt_buf))
		dave_abort();
	return &bt_buf;
#else
/*
//This mincore stuff works, but the bounds tables are not
//sparse enough to make it worthwhile
	unsigned char incore_vec[bt_size / PAGE_SIZE];
 	int incore_ret = mincore(bt_buf, bt_size, &incore_vec[0]);
	if (incore_ret) {
		printf("mincore ret: %d\n", incore_ret);
		perror("mincore");
		dave_abort();
	}
*/
	return (void *)table_vaddr;
#endif
}

int dump_table(unsigned long table_vaddr, unsigned long base_controlled_vaddr, unsigned long bde_vaddr)
{
	unsigned long offset_inside_bt;
	int nr_entries = 0;
	int do_abort = 0;

	//printf("%s() base_controlled_vaddr: 0x%012lx bde_vaddr: 0x%012lx\n", __func__, base_controlled_vaddr, bde_vaddr);

	char *bt_buf = read_bounds_table_into_buf(table_vaddr);

	for (offset_inside_bt = 0;
	     offset_inside_bt < bt_size;
	     offset_inside_bt += bt_entry_size_bytes) {
		unsigned long *bt_entry_buf = (void *)&bt_buf[offset_inside_bt];
		if (!bt_buf) {
			printf("null bt_buf\n");
			abort();
		}
		if (!bt_entry_buf) {
			printf("null bt_entry_buf\n");
			abort();
		}
		//if (!incore_vec[page_nr])
		//	continue;
		if (!bt_entry_buf[0] && !bt_entry_buf[1] && !bt_entry_buf[2] && !bt_entry_buf[3])
			continue;

		nr_entries++;

		unsigned long bt_entry_index = offset_inside_bt/bt_entry_size_bytes;
		unsigned long bt_entry_controls = sizeof(void *);
		unsigned long this_bt_entry_for_vaddr = base_controlled_vaddr + bt_entry_index*bt_entry_controls;
		/*
		 * We sign extend vaddr bits 48->63 which effectively
		 * creates a hole in the virtual address space.
		 * This calculation corrects for the hole.
		 */
		if (this_bt_entry_for_vaddr > 0x00007fffffffffffUL) {
			this_bt_entry_for_vaddr |= 0xffff800000000000;
		}
		if (!vaddr_mapped_by_range(this_bt_entry_for_vaddr)) {
			printf("bt_entry_buf: %p\n", bt_entry_buf);
			printf("there is a bte for %lx but no mapping\n", 
					this_bt_entry_for_vaddr);
			printf("          bde   vaddr: %016lx\n", bde_vaddr);
			printf("base_controlled_vaddr: %016lx\n", base_controlled_vaddr);
			printf("          table_vaddr: %016lx\n", table_vaddr);
			printf("          entry vaddr: %016lx @ offset %lx\n", table_vaddr + offset_inside_bt, offset_inside_bt);
			
			do_abort = 1;
			abort();
		}
		continue;

		printf("table entry[%lx]: ", offset_inside_bt);
		int i;
		for (i = 0; i < bt_entry_size_bytes; i += sizeof(unsigned long))
			printf("0x%016lx ", bt_entry_buf[i]);
		printf("\n");
	}
	if (do_abort)
		abort();
	return nr_entries;
}

int search_bd_buf(char *buf, int len_bytes, unsigned long bd_offset_bytes, int *nr_populated_bdes)
{
	unsigned long i;
	int total_entries = 0;

	dprintf3("%s(%p, %x, %lx, ...)\n", __func__, buf, len_bytes, bd_offset_bytes);

	for (i = 0; i < len_bytes; i += sizeof(unsigned long)) {
		unsigned long bd_index = (bd_offset_bytes + i) / sizeof(unsigned long);
		unsigned long bounds_dir_entry = *(unsigned long *)&buf[i];
		if (!bounds_dir_entry) {
			dprintf4("no bounds dir at index %ld / 0x%lx start at offset:%lx %lx\n", bd_index, bd_index,
					bd_offset_bytes, i);
			continue;
		}
		// mask off the enable bit:
		bounds_dir_entry &= ~0x1;
		dprintf4("found bounds_dir_entry: %lx @ index %lx ptr: %p\n", bounds_dir_entry, i,
					&buf[i]);
		(*nr_populated_bdes)++;

		unsigned long bt_start = bounds_dir_entry;
		unsigned long bt_tail = bounds_dir_entry + bt_size - 1;
		if (!vaddr_mapped_by_range(bt_start)) {
			printf("bounds directory %lx points to nowhere\n", bounds_dir_entry);
			abort();
		}
		if (!vaddr_mapped_by_range(bt_tail)) {
			printf("bounds directory end %lx points to nowhere\n", bt_tail);
			abort();
		}
		// Each bounds directory entry controls 1MB of
		// virtual address space.  This variable is the
		// virtual address in the process of the
		// beginning of the area controlled by this
		// bounds_dir.
		unsigned long bd_for_vaddr = bd_index * (1UL<<20);
		//printf("%s() at bd index: %lx for vaddr: %lx\n", __func__, bd_index, bd_for_vaddr);
		//printf("dir entry[%4ld @ %p]\n", bd_index, bounds_dir_global+i);
		int nr_entries = dump_table(bounds_dir_entry, bd_for_vaddr, bounds_dir_global+bd_offset_bytes+i);
		total_entries += nr_entries;
		continue;
		printf("dir entry[%4ld @ %p]: 0x%lx %6d entries total this buf: %7d bd_for_vaddrs: 0x%lx -> 0x%lx\n",
				bd_index, buf+i,
				bounds_dir_entry, nr_entries, total_entries, bd_for_vaddr, bd_for_vaddr + (1UL<<20));
	}
	return total_entries;
}

int proc_pid_mem_fd = -1;

void *fill_bounds_dir_buf_other(long byte_offset_inside_bounds_dir,
			   long buffer_size_bytes, void *buffer)
{
	unsigned long seekto = bounds_dir_global + byte_offset_inside_bounds_dir;

	off_t seek_ret = lseek(proc_pid_mem_fd, seekto, SEEK_SET);

	if (seek_ret != seekto)
		dave_abort();
	int read_ret = read(proc_pid_mem_fd, buffer, buffer_size_bytes);
	// there shouldn't practically be short reads of /proc/$pid/mem
	if (read_ret != buffer_size_bytes)
		dave_abort();
	return buffer;
}
void *fill_bounds_dir_buf_self(long byte_offset_inside_bounds_dir,
			   long buffer_size_bytes, void *buffer)

{
	unsigned char vec[buffer_size_bytes / PAGE_SIZE];
	char *dig_bounds_dir_ptr = (void *)(bounds_dir_global + byte_offset_inside_bounds_dir);
	/*
	 * use mincore() to quickly find the areas of the bounds directory
	 * that have memory and thus will be worth scanning.
	 */
	int incore_ret;

	int incore = 0;
	int i;

	dprintf4("%s() dig_bounds_dir_ptr: %p\n", __func__, dig_bounds_dir_ptr);

 	incore_ret = mincore(dig_bounds_dir_ptr, buffer_size_bytes, &vec[0]);
	if (incore_ret) {
		printf("mincore ret: %d\n", incore_ret);
		perror("mincore");
		dave_abort();
	}
	for (i = 0; i < sizeof(vec); i++)
		incore += vec[i];
	dprintf4("%s() total incore: %d\n", __func__, incore);
	if (!incore)
		return NULL;
	dprintf3("%s() total incore: %d\n", __func__, incore);
	return dig_bounds_dir_ptr;
}

int inspect_pid(int pid)
{
	long offset_inside_bounds_dir; 
	char bounds_dir_buf[sizeof(unsigned long) * (1UL << 15)];
	char *dig_bounds_dir_ptr;
	int total_entries = 0;
	int nr_populated_bdes = 0;
	int inspect_self;
	
	if (getpid() == pid) {
		dprintf4("inspecting self\n");
		inspect_self = 1;
	} else {
		dprintf4("inspecting pid %d\n", pid);
		abort();
	}

	for (offset_inside_bounds_dir = 0;
	     offset_inside_bounds_dir < bounds_dir_size;
	     offset_inside_bounds_dir += sizeof(bounds_dir_buf)) {
		static int bufs_skipped;
		if (inspect_self) {
			dig_bounds_dir_ptr = fill_bounds_dir_buf_self(offset_inside_bounds_dir,
									sizeof(bounds_dir_buf),
									&bounds_dir_buf[0]);
		} else {
			dig_bounds_dir_ptr = fill_bounds_dir_buf_other(offset_inside_bounds_dir,
									sizeof(bounds_dir_buf),
									&bounds_dir_buf[0]);
		}
		if (!dig_bounds_dir_ptr) {
			bufs_skipped++;
			continue;
		}
		int this_entries = search_bd_buf(dig_bounds_dir_ptr, sizeof(bounds_dir_buf), offset_inside_bounds_dir, &nr_populated_bdes);
		total_entries += this_entries;
		//if (this_entries)
		//	printf("entries this loop: %d total: %d (bufs skipped: %d)\n", this_entries, total_entries, bufs_skipped);
	}
	static int dig_nr = 0;
	printf("mpx dig (%3d) complete, SUCCESS (%8d / %4d)\n", ++dig_nr, total_entries, nr_populated_bdes);
	return total_entries + nr_populated_bdes;
}

#ifndef MPX_DIG_SELF
int main(int argc, char **argv) 
{ 
	int err;
        char *c;
	unsigned long bounds_dir_entry;
	int pid;

	printf("mpx-dig starting...\n");
	err = sscanf(argv[1], "%d", &pid);
	printf("parsing: '%s', err: %d\n", argv[1], err);
	if (err != 1)
		dave_abort();

	err = sscanf(argv[2], "%lx", &bounds_dir_global);
	printf("parsing: '%s': %d\n", argv[2], err);
	if (err != 1)
		dave_abort();

	proc_pid_mem_fd = open_proc(pid, "mem");
	if (proc_pid_mem_fd < 0)
		dave_abort();

	inspect_pid(pid);
	return 0;
}
#endif

long inspect_me(unsigned long bounds_dir)
{
	int pid = getpid();
	pid_load_vaddrs(pid);
	bounds_dir_global = bounds_dir;
	dprintf4("enter %s() bounds dir: %lx\n", __func__, bounds_dir);
	return inspect_pid(pid);
}


