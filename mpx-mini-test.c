/*
 * mpx-mini-test.c: routines to test Intel MPX (Memory Protection eXtentions)
 *
 * INTEL CONFIDENTIAL
 * Copyright (c) 2015, Intel Corporation
 * All rights reserved.
 *
 * Written by:
 * "Ren, Qiaowei" <qiaowei.ren@intel.com>
 * "Wei, Gang" <gang.wei@intel.com>
 * "Hansen, Dave" <dave.hansen@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * 2014-12-05: Dave Hansen: fixed all of the compiler warnings, and made sure
 * 	       it works on 32-bit.
 */

int inspect_every_this_many_mallocs = 100;
int zap_all_every_this_many_mallocs = 1000;

extern long nr_incore(void *ptr, int size_bytes);

#define __always_inline inline __attribute__((always_inline)

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include "mpx-debug.h"
#include "mpx-mm.h"

unsigned int sleep(unsigned int seconds);

#ifdef __i386__

/* i386 directory size is 4MB */
#define NUM_L1_BITS	20
#define NUM_L2_BITS	10
#define NUM_IGN_BITS	2
#define MPX_L2_NODE_ADDR_MASK	0xfffffffcUL

#define REG_IP_IDX	REG_EIP
#define REX_PREFIX 

#define XSAVE_OFFSET_IN_FPMEM	sizeof(struct _libc_fpstate)

/*
 * __cpuid() is from the Linux Kernel:
 */
static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile(
		"push %%ebx;"
		"cpuid;"
		"mov %%ebx, %1;"
		"pop %%ebx"
		: "=a" (*eax),
		  "=g" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

#else /* __i386__ */

/* x86_64 directory size is 2GB */
#define NUM_L1_BITS	28
#define NUM_L2_BITS	17
#define NUM_IGN_BITS	3
#define MPX_L2_NODE_ADDR_MASK	0xfffffffffffffff8ULL

#define REG_IP_IDX	REG_RIP
#define REX_PREFIX "0x48, "

#define XSAVE_OFFSET_IN_FPMEM	0

/*
 * __cpuid() is from the Linux Kernel:
 */
static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile(
		"cpuid;"
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "0" (*eax), "2" (*ecx));
}

#endif /* !__i386__ */

#define BNDSTA_ADDR_MASK	0xfffffffffffffffcULL
#define BNDSTA_REASON_MASK	0xfffffffffffffffcULL

typedef unsigned long ULONG;
typedef ULONG ULONG_MPX;
typedef ULONG_MPX* PULONG_MPX;

const ULONG MPX_L1_SIZE = (1UL << NUM_L1_BITS) * sizeof(ULONG);
const ULONG MPX_MAX_L1_INDEX = (1UL << NUM_L1_BITS);
const ULONG MPX_L2_NODE_SIZE = (1UL << NUM_L2_BITS) * (sizeof(ULONG) * 4);

typedef union {
	struct {
		ULONG ignored:NUM_IGN_BITS;
		ULONG l2entry:NUM_L2_BITS;
		ULONG l1index:NUM_L1_BITS;
	};
	void *pointer;
} mpx_pointer;

typedef struct {
	ULONG_MPX lb;
	ULONG_MPX ub;
	void *OP;
	ULONG_MPX meta_data;
} mpx_l2_entry;

struct xsave_hdr_struct {
	uint64_t xstate_bv;
	uint64_t reserved1[2];
	uint64_t reserved2[5];
} __attribute__((packed));

struct bndregs_struct {
	uint64_t bndregs[8];
} __attribute__((packed));

struct bndcsr_struct {
	uint64_t cfg_reg_u;
	uint64_t status_reg;
} __attribute__((packed));

struct xsave_struct {
	uint8_t fpu_sse[512];
	struct xsave_hdr_struct xsave_hdr;
	uint8_t ymm[256];
	uint8_t lwp[128];
	struct bndregs_struct bndregs;
	struct bndcsr_struct bndcsr;
} __attribute__((packed));

uint8_t __attribute__((__aligned__(64))) buffer[4096];
struct xsave_struct *xsave_buf = (struct xsave_struct *)buffer;

uint8_t __attribute__((__aligned__(64))) test_buffer[4096];
struct xsave_struct *xsave_test_buf = (struct xsave_struct *)test_buffer;

//unsigned int xsave_plc_offset = 0;
uint64_t num_bnd_chk = 0;

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

static __always_inline void xrstor_state(struct xsave_struct *fx, uint64_t mask)
{
        uint32_t lmask = mask;
        uint32_t hmask = mask >> 32;

        asm volatile(".byte " REX_PREFIX "0x0f,0xae,0x2f\n\t"
                     : : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
                     :   "memory");
}

static __always_inline void xsave_state_1(void *_fx, uint64_t mask)
{
        uint32_t lmask = mask;
        uint32_t hmask = mask >> 32;
	unsigned char *fx = _fx;

        asm volatile(".byte " REX_PREFIX "0x0f,0xae,0x27\n\t"
                     : : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
                     :   "memory");
}

static inline uint64_t xgetbv(uint32_t index)
{
	uint32_t eax, edx;

	asm volatile(".byte 0x0f,0x01,0xd0" /* xgetbv */
		     : "=a" (eax), "=d" (edx)
		     : "c" (index));
	return eax + ((uint64_t)edx << 32);
}

/*
static uint64_t read_mpx_status()
{
	memset(buffer, 0, sizeof(buffer));
	xsave_state_1(xsave_buf, 0x18);
	//print_buffer(buffer, sizeof(*xsave_buf));

	//printf("xsave cndcsr: status %llx, configu %llx\n",
	//       xsave_buf->bndcsr.status_reg, xsave_buf->bndcsr.cfg_reg_u);
	return xsave_buf->bndcsr.status_reg;
}
*/

static uint64_t read_mpx_status_sig(ucontext_t *uctxt)
{
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer,
		(uint8_t *)uctxt->uc_mcontext.fpregs + XSAVE_OFFSET_IN_FPMEM,
		sizeof(struct xsave_struct));
	//print_buffer(buffer, sizeof(*xsave_buf));

	//printf("xsave cndcsr: status %llx, configu %llx\n",
	//       xsave_buf->bndcsr.status_reg, xsave_buf->bndcsr.cfg_reg_u );
	return xsave_buf->bndcsr.status_reg;
}

#include <pthread.h>

static uint8_t *get_next_inst_ip(uint8_t *addr)
{
	uint8_t *ip = addr;	

	uint8_t  sib;

	/*
	* determine the prefix.
	*/
	switch(*ip) {
	case 0xf2:
	case 0xf3:
	case 0x66:
		ip++;
		break;
	}

	/*
	* look for rex prefix
	*/
	if ((*ip & 0x40) == 0x40) {
		ip++;
	}

	/*
	* Make sure we have a MPX instruction.
	*/
	if (*ip++ != 0x0f) {    
		return addr;
	}

	/*
	* Skip the op code byte.
	*/
	ip++;

	/*
	* Get the moderm byte.
	*/
	uint8_t modrm = *ip++;

	/*
	* Break it down into parts.
	*/
	uint8_t rm = modrm & 7;
	uint8_t mod = (modrm >> 6);

	/*
	* Init the parts of the address mode.
	*/
	uint8_t base = 8;

	/*
	* Is it a mem mode?
	*/
	if (mod != 3) {
		// look for scaled indexed addressing
		if (rm == 4) {
			// SIB addressing
			sib = *ip++;
			//uint8_t ss = sib >> 6;
			base = sib & 7;
			switch (mod) 
			{
			case 0:
				if (base == 5) {
					ip += 4;
				}
				break;

			case 1:
				ip++;
				break;

			case 2:
				ip += 4;
				break;
			}

		} else {
			// MODRM addressing
			switch(mod) 
			{
			case 0:
				if (rm == 5) {
					// DISP32 addressing, no base
					ip += 4;
				}
				break;

			case 1:
				ip++;
				break;

			case 2:
				ip += 4;
				break;
			}
		}
	}
	//for (; addr < ip; addr++)
	//	printf("%02x ", *addr);
	//printf("\n");
	return ip;	
}

static int br_count = 0;

void handler(int signum, siginfo_t* si, void* vucontext)
{
	int i;
	ucontext_t* uctxt = vucontext;
	int trapno;
	unsigned long ip;
	trapno = uctxt->uc_mcontext.gregs[REG_TRAPNO];
	ip = uctxt->uc_mcontext.gregs[REG_IP_IDX];

	if (trapno == 5) {
		typeof(si->si_addr) *si_addr_ptr = &si->si_addr;
		uint64_t status = read_mpx_status_sig(uctxt);
		//uint64_t status = read_mpx_status();
		uint64_t br_reason =  status & 0x3;
		br_count++;
		dprintf1("#BR 0x%jx (total seen: %d)\n", status, br_count);

#define __SI_FAULT      (3 << 16)
#define SEGV_BNDERR     (__SI_FAULT|3)  /* failed address bound checks */

		dprintf2("Saw a #BR! status 0x%jx at %016lx br_reason: %jx\n", status, ip, br_reason);
		dprintf2("si_signo: %d\n", si->si_signo);
		dprintf2("  signum: %d\n", signum);
		dprintf2("info->si_code == SEGV_BNDERR: %d\n", (si->si_code == SEGV_BNDERR));
		dprintf2("info->si_code: %d\n", si->si_code);
		for (i = 0; i < 8; i++)
			dprintf3("[%d]: %p\n", i, si_addr_ptr[i]);
		switch (br_reason) {
		case 0: /* traditional BR */
			fprintf(stderr,
				"Undefined status with bound exception:%jx\n",
				 status);
			exit(5);
		case 1: /* #BR MPX bounds exception */
			// these are normal and we expect to see them
			dprintf1("bounds exception (normal): status 0x%jx at %p si_addr: %p\n",
				status, (void *)ip, si->si_addr);
			num_bnd_chk++;
			uctxt->uc_mcontext.gregs[REG_IP_IDX] =
				(greg_t)get_next_inst_ip((uint8_t *)ip);
			break;
		case 2:
			fprintf(stderr, "#BR status == 2, missing bounds table, kernel should have handled!!\n");
			exit(4);
			break;
		default:
			fprintf(stderr, "bound check error: status 0x%jx at %p\n",
				status, (void *)ip);
			num_bnd_chk++;
			uctxt->uc_mcontext.gregs[REG_IP_IDX] =
				(greg_t)get_next_inst_ip((uint8_t *)ip);
			fprintf(stderr, "bound check error: si_addr %p\n", si->si_addr);
			exit(3);
		}
	} else if (trapno == 14) {
		fprintf(stderr,
			"ERROR: In signal handler, page fault, trapno = %d, ip = %016lx\n",
			trapno, ip);
		fprintf(stderr, "si_addr %p\n", si->si_addr);
		fprintf(stderr, "REG_ERR: %lx\n", (unsigned long)uctxt->uc_mcontext.gregs[REG_ERR]);
		sleep(999);
		exit(1);
	} else {
		fprintf(stderr,"unexpected trap %d! at 0x%lx\n", trapno, ip);
		fprintf(stderr, "si_addr %p\n", si->si_addr);
		fprintf(stderr, "REG_ERR: %lx\n", (unsigned long)uctxt->uc_mcontext.gregs[REG_ERR]);
		sleep(999);
		exit(2);
	}
}

static inline void cpuid_count(unsigned int op, int count,
                               unsigned int *eax, unsigned int *ebx,
                               unsigned int *ecx, unsigned int *edx)
{
        *eax = op;
        *ecx = count;
        __cpuid(eax, ebx, ecx, edx);
}

bool check_mpx_support()
{
	unsigned int eax, ebx, ecx, edx;

	cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
        printf("features 0x%x\n", ecx);

	if ((!(ecx & (1 << 26))) || (!(ecx & (1 << 27))))
		return false;

        printf("XSAVE is supported by HW & OS\n");

	cpuid_count(0, 0, &eax, &ebx, &ecx, &edx);

        printf("max cpuid leaf is 0x%x\n", eax);

	if (eax < 0xD)
		return false;

	cpuid_count(0xD, 0, &eax, &ebx, &ecx, &edx);

        printf("xsave supported states: 0x%x\n", eax);

	if ((eax & 0x18) != 0x18)
		return false;

	if ((xgetbv(0) & 0x18) != 0x18)
		return false;
	//cpuid_count(0xD, 4, &eax, &ebx, &ecx, &edx);
        //printf("MPX configu offset: 0x%x\n", ebx);

	//xsave_plc_offset = ebx;
	return true;
}

void enable_pl(void* l1base)
{
	/* enable point lookup */
	memset(buffer, 0, sizeof(buffer));
	//printf("sizeof struct xsave_struct %d\n", sizeof(struct xsave_struct));
	xrstor_state(xsave_buf, 0x18);

	xsave_buf->xsave_hdr.xstate_bv = 0x10;
	xsave_buf->bndcsr.cfg_reg_u = (unsigned long)l1base | 1;
	//xsave_buf->bndcsr.cfg_reg_u |= 2; // set bndpreserve
	xsave_buf->bndcsr.status_reg = 0;

	printf("bf xrstor\n");
	printf("xsave cndcsr: status %jx, configu %jx\n",
	       xsave_buf->bndcsr.status_reg, xsave_buf->bndcsr.cfg_reg_u );
	xrstor_state(xsave_buf, 0x18);
	printf("after xrstor\n");

	xsave_state_1(xsave_buf, 0x18);
	//print_buffer(buffer, sizeof(*xsave_buf));

	printf("xsave cndcsr: status %jx, configu %jx\n",
	       xsave_buf->bndcsr.status_reg, xsave_buf->bndcsr.cfg_reg_u);
}

#include <sys/prctl.h>
unsigned long *bounds_dir_ptr;

unsigned long __bd_incore(const char *func, int line)
{
	unsigned long ret = nr_incore(bounds_dir_ptr, MPX_L1_SIZE);
	//printf("%s()::%d incore: %ld\n", func, line, ret);
	return ret;
}
#define bd_incore() __bd_incore(__func__, __LINE__)

bool process_specific_init(void)
{
	unsigned long size;
	unsigned long *dir;
	unsigned long _dir;
  
	size = 2UL << 31; // 2GB
	if (sizeof(unsigned long) == 4)
		size = 4UL << 20; // 4MB
	size += 4096; // Guarantee we have the space to align it
//	dir = malloc(size);
	dir = mmap((void *)0x200000000000, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	madvise(dir, size, MADV_NOHUGEPAGE);
	_dir = (unsigned long)dir;
	_dir += 0xfffUL;
	_dir &= ~0xfffUL;
	dir = (void *)_dir;
	bounds_dir_ptr = dir;
	bd_incore();
	if (0) {
		unsigned long i;
		for (i = 0; i < size / sizeof(unsigned long); i++) {
			// point it up at the kernel address space
#ifdef __x86_64__  
			dir[i] = 0xffffffff00000001UL;
#else
			dir[i] = 0xffff0001UL;
#endif
			//dir[i] &= ~0x1;
		}
	}
	printf("dir: 0x%p -> 0x%lx\n", dir, _dir + size);
	enable_pl(dir);
	if (prctl(43, 0, 0, 0, 0)) {
		printf("no MPX support\n");
		abort();		
		return false;
	}

	return true;
}

bool process_specific_finish(void)
{
    if (prctl(44)) {
	    printf("no MPX support\n");
	    return false;
    }

    return true;
}

void setup_handler()
{
	int r,rs;
	struct sigaction newact;
	struct sigaction oldact;

	/* #BR is mapped to sigsegv */
	int signum  = SIGSEGV;

	newact.sa_handler = 0;   /* void(*)(int)*/
	newact.sa_sigaction = handler; /* void (*)(int, siginfo_t*, void*) */

	/*sigset_t - signals to block while in the handler */
	/* get the old signal mask. */
	rs = sigprocmask(SIG_SETMASK, 0, &newact.sa_mask);
	assert(rs == 0);

	/* call sa_sigaction, not sa_handler*/
	newact.sa_flags = SA_SIGINFO;

	newact.sa_restorer = 0;  /* void(*)(), obsolete */
	r = sigaction(signum, &newact, &oldact);
	assert(r == 0);
}

void mpx_prepare(void)
{
	printf("pl: hello...\n");
	setup_handler();
	process_specific_init();
}

void mpx_cleanup(void)
{
	printf("pl: %jd BRs. bye...\n", num_bnd_chk);
	//process_specific_finish();
}

/*-------------- the following is test case ---------------*/
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

//typedef unsigned long ULONG_MPX;
//typedef unsigned long ULONG;

//#ifdef __i386__
//#define REX_PREFIX
//#else
//#define REX_PREFIX "0x48,"
//#endif

uint64_t shadow_plb[4][2]; // shadow MPX bound registers
//uint64_t shadow_plc, shadow_pls;  // shadow config and status registers 
ULONG_MPX shadow_map[4];
uint64_t num_lower_brs = 0;
uint64_t num_upper_brs = 0;

#define MPX_CONFIG_OFFSET 1024
#define MPX_BOUNDS_OFFSET 960
#define MPX_HEADER_OFFSET 512
#define MAX_ADDR_TESTED (1<<28)
#define TEST_ROUNDS 100

/*
      0F 1A /r BNDLDX—Load
      0F 1B /r BNDSTX—Store Extended Bounds Using Address Translation
   66 0F 1A /r BNDMOV bnd1, bnd2/m128
   66 0F 1B /r BNDMOV bnd1/m128, bnd2
   F2 0F 1A /r BNDCU bnd, r/m64
   F2 0F 1B /r BNDCN bnd, r/m64
   F3 0F 1A /r BNDCL bnd, r/m64 
   F3 0F 1B /r BNDMK bnd, m64
*/

static __always_inline void xsave_state(void *_fx, uint64_t mask)
{
        uint32_t lmask = mask;
        uint32_t hmask = mask >> 32;
	unsigned char *fx = _fx;
	

        asm volatile(".byte " REX_PREFIX "0x0f,0xae,0x27\n\t"
                     : : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
                     :   "memory");
}

static __always_inline void mpx_clear_bnd0(void)
{
	long size = 0;
	void *ptr = NULL;
   	// F3 0F 1B /r BNDMK bnd, m64
	// f3 0f 1b 04 11       	bndmk  (%rcx,%rdx,1),%bnd0
        asm volatile(".byte " "0xf3,0x0f,0x1b,0x04,0x11\n\t"
                     : : "c" (ptr), "d" (size-1)
                     :   "memory");
}

static __always_inline void mpx_make_bound_helper(ULONG_MPX ptr, ULONG_MPX size)
{
   	// F3 0F 1B /r BNDMK bnd, m64
	// f3 0f 1b 04 11       	bndmk  (%rcx,%rdx,1),%bnd0
        asm volatile(".byte " "0xf3,0x0f,0x1b,0x04,0x11\n\t"
                     : : "c" (ptr), "d" (size-1)
                     :   "memory");
}


static __always_inline void mpx_check_lowerbound_helper(ULONG_MPX ptr)
{
	// F3 0F 1A /r BNDCL bnd, r/m64 
	// f3 0f 1a 01          	bndcl  (%rcx),%bnd0
        asm volatile(".byte " "0xf3,0x0f,0x1a,0x01\n\t"
                     : : "c" (ptr)
                     :   "memory");
}

static __always_inline void mpx_check_upperbound_helper(ULONG_MPX ptr)
{
	// F2 0F 1A /r BNDCU bnd, r/m64
	// f2 0f 1a 01          	bndcu  (%rcx),%bnd0
        asm volatile(".byte " "0xf2,0x0f,0x1a,0x01\n\t"
                     : : "c" (ptr)
                     :   "memory");
}

static __always_inline void mpx_movbndreg_helper()
{
	// 66 0F 1B /r BNDMOV bnd1/m128, bnd2
	// 66 0f 1b c2          	bndmov %bnd0,%bnd2

        asm volatile(".byte " "0x66,0x0f,0x1b,0xc2\n\t");
}

static __always_inline void mpx_movbnd2mem_helper(uint8_t *mem)
{
	// 66 0F 1B /r BNDMOV bnd1/m128, bnd2
	// 66 0f 1b 01          	bndmov %bnd0,(%rcx)
        asm volatile(".byte " "0x66,0x0f,0x1b,0x01\n\t"
                     : : "c" (mem)
                     :   "memory");
}

static __always_inline void mpx_movbnd_from_mem_helper(uint8_t *mem)
{
	// 66 0F 1A /r BNDMOV bnd1, bnd2/m128
	// 66 0f 1a 01          	bndmov (%rcx),%bnd0
        asm volatile(".byte " "0x66,0x0f,0x1a,0x01\n\t"
                     : : "c" (mem)
                     :   "memory");
}

static __always_inline void mpx_store_dsc_helper(ULONG_MPX ptr_addr, ULONG_MPX ptr_val)
{
	// 0F 1B /r BNDSTX—Store Extended Bounds Using Address Translation
	// 0f 1b 04 11          	bndstx %bnd0,(%rcx,%rdx,1)
        asm volatile(".byte " "0x0f,0x1b,0x04,0x11\n\t"
                     : : "c" (ptr_addr), "d" (ptr_val)
                     :   "memory");
}

static __always_inline void mpx_load_dsc_helper(ULONG_MPX ptr_addr, ULONG_MPX ptr_val)
{
	// 0F 1A /r BNDLDX—Load
	// 0f 1a 04 11          	bndldx (%rcx,%rdx,1),%bnd0
        asm volatile(".byte " "0x0f,0x1a,0x04,0x11\n\t"
                     : : "c" (ptr_addr), "d" (ptr_val)
                     :   "memory");
}

/*
static void print_buffer(uint8_t *buf, int size)
{
	int i;
	for (i = 0; i < size; i++) {
		printf("%02x ", buf[i]);
		if ( i % 32 == 31 )
			printf("\n");
	}

	printf("\n\n");
}*/

void __print_context(void *__print_xsave_buffer, int line)
{
	uint64_t *bounds = (uint64_t *)(__print_xsave_buffer + MPX_BOUNDS_OFFSET);
	uint64_t *cfg    = (uint64_t *)(__print_xsave_buffer + MPX_CONFIG_OFFSET);

	int i;
	printf("%s()::%d\n", "print_context", line);
	for (i = 0; i < 4; i++) {
		printf("bound[%d]: 0x%016lx 0x%016lx(0x%016lx)\n", i,
		       (ULONG_MPX)bounds[i*2], ~(ULONG_MPX)bounds[i*2+1], (ULONG_MPX)bounds[i*2+1]);
	}

	printf("cpcfg: %jx  cpstatus: %jx\n", cfg[0], cfg[1]);
}
#define print_context(x) __print_context(x, __LINE__)
#ifdef DEBUG
#define dprint_context(x) print_context(x)
#else
#define dprint_context(x) do{}while(0)
#endif

void init()
{
	srand((unsigned int)time(NULL));

	int i;
	for (i = 0; i < 4; i++) {
		shadow_plb[i][0] = 0;
		shadow_plb[i][1] = ~(ULONG_MPX)0;
	}
}

long int __daverandom(int line)
{
	static long fake = 722122311;
	fake += 563792075;
	long int ret;
	ret = random();
//	ret = fake;
//	printf("random @ %d: %10ld\n", line, ret);
	return ret;
}
#define daverandom() __daverandom(__LINE__)


uint8_t *get_random_addr()
{	
	uint8_t*addr = (uint8_t *)(unsigned long)(rand() % MAX_ADDR_TESTED);
	return (addr - (ULONG_MPX)addr % sizeof(uint8_t *));
}

static inline bool compare_context(void *__xsave_buffer)
{
	uint64_t *bounds = (uint64_t *)(__xsave_buffer + MPX_BOUNDS_OFFSET);
	//uint64_t *cfg = (uint64_t *)(&xsave_buffer[MPX_CONFIG_OFFSET]);

	int i;
	for (i = 0; i < 4; i++) {
		/* printf("bound %d\n", i);
		//printf("shadow{%llx/%llx}\nbounds{%llx/%llx}\n",
		//       shadow_plb[i][0], shadow_plb[i][1],
		//       bounds[i*2], bounds[i*2+1]);
		printf("shadow{%lx/%lx}\nbounds{%lx/%lx}\n",
		       (ULONG_MPX)shadow_plb[i][0], (ULONG_MPX)shadow_plb[i][1],
		       (ULONG_MPX)bounds[i*2], (ULONG_MPX)bounds[i*2+1]); */
		if ((shadow_plb[i][0] != bounds[i*2]) ||
		    (shadow_plb[i][1] != ~(ULONG_MPX)bounds[i*2+1])) {
			printf("ERROR comparing shadow to real bound register %d\n", i);
			printf("shadow{0x%016lx/0x%016lx}\nbounds{0x%016lx/0x%016lx}\n",
			       (ULONG_MPX)shadow_plb[i][0], (ULONG_MPX)shadow_plb[i][1],
			       (ULONG_MPX)bounds[i*2], (ULONG_MPX)bounds[i*2+1]);
			return false;
		}
	}

	return true;
}
	
void mkbnd_shadow(uint8_t *ptr, int index, long offset)
{
	uint64_t *lower = (uint64_t *)&(shadow_plb[index][0]);
	uint64_t *upper = (uint64_t *)&(shadow_plb[index][1]);
	*lower = (ULONG_MPX)ptr;
	*upper = (ULONG_MPX)ptr + offset - 1;
}

void check_lowerbound_shadow(uint8_t *ptr, int index)
{
	uint64_t *lower = (uint64_t *)&(shadow_plb[index][0]);
	if (*lower > (uint64_t)(ULONG_MPX)ptr)
		num_lower_brs++;
	else
		dprintf1("LowerBoundChk passed:%p\n", ptr);
}

void check_upperbound_shadow(uint8_t *ptr, int index)
{
	uint64_t upper = *(ULONG_MPX *)&(shadow_plb[index][1]);
	if (upper < (uint64_t)(ULONG_MPX)ptr)
		num_upper_brs++;
	else
		dprintf1("UpperBoundChk passed:%p\n", ptr);
}

void __always_inline movbndreg_shadow(int src, int dest)
{
	shadow_plb[dest][0] = shadow_plb[src][0];
	shadow_plb[dest][1] = shadow_plb[src][1];
}

void __always_inline movbnd2mem_shadow(int src, ULONG_MPX *dest)
{
	ULONG_MPX *lower = (ULONG_MPX *)&(shadow_plb[src][0]);
	ULONG_MPX *upper = (ULONG_MPX *)&(shadow_plb[src][1]);
	*dest = *lower;
	*(dest+1) = *upper;
}

void __always_inline movbnd_from_mem_shadow(ULONG_MPX *src, int dest)
{
	ULONG_MPX *lower = (ULONG_MPX *)&(shadow_plb[dest][0]);
	ULONG_MPX *upper = (ULONG_MPX *)&(shadow_plb[dest][1]);
	*lower = *src;
	*upper = *(src+1);
}

void __always_inline stdsc_shadow(int index, uint8_t *ptr, uint8_t *ptr_val)
{
	shadow_map[0] = (ULONG_MPX)shadow_plb[index][0];
	shadow_map[1] = (ULONG_MPX)shadow_plb[index][1];
	shadow_map[2] = (ULONG_MPX)ptr_val;
	//ptr ignored
}

void lddsc_shadow(int index, uint8_t *ptr, uint8_t *ptr_val)
{
	uint64_t lower = shadow_map[0];
	uint64_t upper = shadow_map[1];
	uint8_t *value = (uint8_t *)shadow_map[2];
	if (value != ptr_val) {
		shadow_plb[index][0] = 0;
		shadow_plb[index][1] = ~(ULONG_MPX)0;
	} else {
		shadow_plb[index][0] = lower;
		shadow_plb[index][1] = upper;
	}
	//ptr ignorec
}

static __always_inline void mpx_test_helper0(uint8_t *buf, uint8_t *ptr)
{
	mpx_make_bound_helper((ULONG_MPX)ptr, 0x1800);
}

static __always_inline void mpx_test_helper0_shadow(uint8_t *buf, uint8_t *ptr)
{
	mkbnd_shadow(ptr, 0, 0x1800);
}

static __always_inline void mpx_test_helper1(uint8_t *buf, uint8_t *ptr)
{
	mpx_check_lowerbound_helper((ULONG_MPX)(ptr-1));
	mpx_check_upperbound_helper((ULONG_MPX)(ptr+0x1800));
}

static __always_inline void mpx_test_helper1_shadow(uint8_t *buf, uint8_t *ptr)
{
	check_lowerbound_shadow(ptr-1, 0);
	check_upperbound_shadow(ptr+0x1800, 0);
}

static __always_inline void mpx_test_helper2(uint8_t *buf, uint8_t *ptr)
{
	mpx_make_bound_helper((ULONG_MPX)ptr, 0x1800);
	mpx_movbndreg_helper();
	mpx_movbnd2mem_helper(buf);
	mpx_make_bound_helper((ULONG_MPX)(ptr+0x12), 0x1800);
}

static __always_inline void mpx_test_helper2_shadow(uint8_t *buf, uint8_t *ptr)
{
	mkbnd_shadow(ptr, 0, 0x1800);
	movbndreg_shadow(0, 2);
	movbnd2mem_shadow(0, (ULONG_MPX *)buf);
	mkbnd_shadow(ptr+0x12, 0, 0x1800);
}

static __always_inline void mpx_test_helper3(uint8_t *buf, uint8_t *ptr)
{
	mpx_movbnd_from_mem_helper(buf);
}

static __always_inline void mpx_test_helper3_shadow(uint8_t *buf, uint8_t *ptr)
{
	movbnd_from_mem_shadow((ULONG_MPX *)buf, 0);
}

static __always_inline void mpx_test_helper4(uint8_t *buf, uint8_t *ptr)
{
	mpx_store_dsc_helper((ULONG_MPX)buf, (ULONG_MPX)ptr);
	mpx_make_bound_helper((ULONG_MPX)(ptr+0x12), 0x1800); 
}

static __always_inline void mpx_test_helper4_shadow(uint8_t *buf, uint8_t *ptr)
{
	stdsc_shadow(0, buf, ptr);
	mkbnd_shadow(ptr+0x12, 0, 0x1800);
}

static __always_inline void mpx_test_helper5(uint8_t *buf, uint8_t *ptr)
{
	mpx_clear_bnd0();
	mpx_load_dsc_helper((ULONG_MPX)buf, (ULONG_MPX)ptr);
	mpx_clear_bnd0();
}

static __always_inline void mpx_test_helper5_shadow(uint8_t *buf, uint8_t *ptr)
{
	lddsc_shadow(0, buf, ptr);
}

/*
 * For compatability reasons, MPX will clear the bounds registers
 * when you make function calls (among other things).  We have to
 * preserve the registers in between calls to the "helpers" since
 * they build on each other.
 *
 * Be very careful not to make any function calls inside the
 * helpers, or anywhere else beween the xrstor and xsave.
 */
#define run_helper(helper_nr, buf, buf_shadow, ptr)	do {	\
	xrstor_state(xsave_test_buf, flags);			\
	mpx_test_helper##helper_nr(buf, ptr);			\
	xsave_state(xsave_test_buf, flags);			\
	mpx_test_helper##helper_nr##_shadow(buf_shadow, ptr);	\
} while(0)

static void run_helpers(int nr, uint8_t *buf, uint8_t *buf_shadow, uint8_t *ptr)
{
	uint64_t flags = 0x18;
	dprint_context(xsave_test_buf);
	switch (nr) {
		case 0: run_helper(0, buf, buf_shadow, ptr); break;
		case 1: run_helper(1, buf, buf_shadow, ptr); break;
		case 2: run_helper(2, buf, buf_shadow, ptr); break;
		case 3: run_helper(3, buf, buf_shadow, ptr); break;
		case 4: run_helper(4, buf, buf_shadow, ptr); break;
		case 5: run_helper(5, buf, buf_shadow, ptr); break;
		default:
			abort();
			break;
	}
	dprint_context(xsave_test_buf);
}

/*
struct mpx_test_t {
	void (*helper)(uint8_t *buf, uint8_t *ptr);
	void (*helper_shadow)(uint8_t *buf, uint8_t *ptr);
} mpx_test[] = {
	{mpx_test_helper0, mpx_test_helper0_shadow},
	{mpx_test_helper1, mpx_test_helper1_shadow},
	{mpx_test_helper2, mpx_test_helper2_shadow},
	{mpx_test_helper3, mpx_test_helper3_shadow},
	{mpx_test_helper4, mpx_test_helper4_shadow},
	{mpx_test_helper5, mpx_test_helper5_shadow}
};
*/

//ULONG_MPX buf[1024];
ULONG_MPX buf_shadow[1024]; // used to check load / store descriptors
extern long inspect_me(unsigned long *bounds_dir);

long cover_buf_with_bt_entries(void *buf, long buf_len)
{
	int i;
	long nr_to_fill;
	int ratio = 1000;
	
	// Fill about 1/100 of the space with bt entries
	nr_to_fill = buf_len / (sizeof(unsigned long) * ratio);
	//if (!(daverandom() % 10))
	//	nr_to_fill = 0;

	if (!nr_to_fill)
		dprintf3("%s() nr_to_fill: %ld\n", __func__, nr_to_fill);

	// Align the buffer to pointer size
	while (((unsigned long)buf) % sizeof(void *)) {
		buf++;
		buf_len--;
	}
	// We are storing pointers, so make 
	unsigned long buf_len_in_ptrs = buf_len / sizeof(void *);

	for (i = 0; i < nr_to_fill; i++) {
		long index = (daverandom() % buf_len_in_ptrs);
		void *ptr = buf + index * sizeof(unsigned long);
		unsigned long ptr_addr = (unsigned long)ptr;;
		//printf("random index: %ld\n", index);

		// ptr and size can be anything
		// put ptr->size in to bnd0
		mpx_make_bound_helper((unsigned long)ptr, 8);

		// take bnd0 and put it in to bounds tables
		// "buf + index" is an address inside the buffer where
		// we are pretending that we are going to put a pointer
		// We do not, though because we will never load entries
		// from the table, so it doesn't matter.
		mpx_store_dsc_helper(ptr_addr, (unsigned long)ptr);
		dprintf4("storing bound table entry for %lx (buf start @ %p)\n", ptr_addr, buf);
	}
	return nr_to_fill;
}

unsigned long align_down(unsigned long alignme, unsigned long align_to)
{
	return alignme & ~(align_to-1);
}

unsigned long align_up(unsigned long alignme, unsigned long align_to)
{
	return (alignme + align_to - 1) & ~(align_to-1);
}

/*
 * Using 1MB alignment guarantees that each no allocation
 * will overlap with another's bounds tables.
 * 
 * We have to cook our own allocator here.  malloc() can
 * mix other allocation with ours which means that even
 * if we free all of our allocations, there might still
 * be bounds tables for the *areas* since there is other
 * valid memory there.
 *
 * We also can't use malloc() because a free() of an area
 * might not free it back to the kernel.  We want it
 * completely unmapped an malloc() does not guarantee
 * that.
 */
long alignment = 1 *MB;
long sz_alignment = 1 * MB;
void *dave_alloc(unsigned long sz)
{
	static void *last = 0x0;
	void *ptr;

	sz = align_up(sz, sz_alignment);

	void *try_at = last + alignment;
	while (1) {
		ptr = mmap(try_at, sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		//assert(ptr != (void *)-1);
		if (ptr == (void *)-1)
			return NULL;
		if (ptr == try_at)
			break;

		munmap(ptr, sz);
		try_at += alignment;
		if (try_at > (void *)0x0000800000000000)
			try_at = (void *)0x0;
		continue;
	}
	last = ptr;
	return ptr;
}
void dave_free(void *ptr, long sz)
{
		
	dprintf2("%s() ptr: %p\n", __func__, ptr);
	if ((unsigned long)ptr > 0x100000000000) {
		dprintf1("uh oh !!!!!!!!!!!!!!! pointer too high: %p\n", ptr);
		abort();
	}
	sz = align_up(sz, sz_alignment);
	munmap(ptr, sz);
}

#define NR_MALLOCS 100
struct one_malloc {
	char *ptr;
	int nr_filled_btes;
	unsigned long size;
};
struct one_malloc mallocs[NR_MALLOCS];

void free_one_malloc(int index)
{
	unsigned long free_ptr;
	unsigned long mask;
//	long before = 0;
//	long after = 0;

	if (!mallocs[index].ptr)
		return;

//	if (!mallocs[index].nr_filled_btes) {
//		before = inspect_me(bounds_dir_ptr);
//	}
	dave_free(mallocs[index].ptr, mallocs[index].size);
	dprintf4("freed[%d]:  %p\n", index, mallocs[index].ptr);

	free_ptr = (unsigned long)mallocs[index].ptr;
	mask = (1UL<<20)-1;
	dprintf4("lowerbits: %lx / %lx mask: %lx\n", free_ptr, (free_ptr & mask), mask);
	assert((free_ptr & mask) == 0);

	mallocs[index].ptr = NULL;
//	if (!mallocs[index].nr_filled_btes) {
//		after = inspect_me(bounds_dir_ptr);
//	}
//	if (before != after) {
//		printf("free empty area, but nr entries changed\n");
//		abort();
//	}
}

void zap_everything(void)
{
	long after_zap;
	dprintf2("zapping everything\n");
	int i;
	inspect_me(bounds_dir_ptr);
	for (i = 0; i < NR_MALLOCS; i++)
		free_one_malloc(i);
	after_zap = inspect_me(bounds_dir_ptr);
	dprintf3("zapping everything done: %ld\n", after_zap);
	// We only guarantee to empty the thing out if
	// our allocations are exactly aligned on the
	// boundaries of a boudns table.
	if ((alignment == 1*MB) &&
	    (sz_alignment == 1*MB)) {
		if (after_zap != 0) {
			printf("not empty after total zap\n");
			sleep(9999);
		}
		assert(after_zap == 0);
	}
}

int do_one_malloc(void)
{
	int rand_index = (daverandom() % NR_MALLOCS);
	void *ptr = mallocs[rand_index].ptr;

	dprintf4("%s() enter\n", __func__);

	if (ptr) {
		free_one_malloc(rand_index);
		if (daverandom() % (NR_MALLOCS*3) == 3) {
			int i;
			dprintf3("zapping some more\n");
			for (i = rand_index; i < NR_MALLOCS; i++) {
				free_one_malloc(i);
			}
		}
		if ((daverandom() % zap_all_every_this_many_mallocs) == 4)
			zap_everything();
	}

	// 1->~1M
	long sz = (1 + daverandom() % 1000) * 1000;
	sz_alignment = PAGE_SIZE;
	ptr = dave_alloc(sz);
	if (!ptr) {
		// If we are failing allocations, just assume we
		// are out of memory and zap everything.
		dprintf1("zapping everything because out of memory\n");
		zap_everything();
		return -1;
	}

	dprintf4("malloc: %p size: 0x%lx\n", ptr, sz);
	mallocs[rand_index].nr_filled_btes = cover_buf_with_bt_entries(ptr, sz);
	mallocs[rand_index].ptr = ptr;
	mallocs[rand_index].size = sz;

	return rand_index;
}

void check_bounds_table_frees(void)
{
	int i;

	dprintf4("%s() enter\n", __func__);

	inspect_me(bounds_dir_ptr);
	for (i = 0; i < 1000000; i++) {
		do_one_malloc();
		if (i % inspect_every_this_many_mallocs == 0)
			inspect_me(bounds_dir_ptr);
	}
}

void check_mpx_insns_and_tables(void)
{
	int successes = 0;
	int failures  = 0;
	int tries = 0;
	int buf_size = (1024*1024);
	unsigned long *buf = malloc(buf_size);
	int i, j;

	memset(buf, 0, buf_size);
	memset(buf_shadow, 0, sizeof(buf_shadow));

	for (i = 0; i < TEST_ROUNDS; i++) {
		for (j = 0; j <= 5; j++) {
			tries++;
			dprintf1("\nstarting test nr %d\n", tries);
			dprint_context(xsave_test_buf);
			// test j+1
			uint8_t *ptr = get_random_addr() + 8;
			dprintf3("random ptr{%p}\n", ptr);
			dprint_context(xsave_test_buf);
			run_helpers(j, (void *)buf, (void *)buf_shadow, ptr);
			dprint_context(xsave_test_buf);
			if (!compare_context(xsave_test_buf)) {
				print_context(xsave_test_buf);
				printf("ERROR: test %d failed\n", tries);
				sleep(99999);
				failures++;
				goto exit;
			}
			successes++;
			dprint_context(xsave_test_buf);
			dprintf1("finished test %d\n", tries);
			dprint_context(xsave_test_buf);
		}
	}

exit:
	dprintf2("\nabout to free:\n");
	free(buf);
	printf("successes: %d\n", successes);
	printf(" failures: %d\n", failures);
	printf("    tries: %d\n", tries);
	printf(" expected: %jd #BRs\n", num_upper_brs + num_lower_brs);
	printf("      saw: %d #BRs\n", br_count);
	if (failures) {
		printf("ERROR: non-zero number of failures\n");
		exit(20);
	}
	if (successes != tries) {
		printf("ERROR: succeded fewer than number of tries\n");
		exit(21);
	}
	if (num_upper_brs + num_lower_brs != br_count) {
		printf("ERROR: unexpected number of #BRs\n");
		exit(22);
	}
	printf("\n");
	static int iterations = 0;
	printf("ALL TESTS PASSED!! (iteration %d)\n\n", ++iterations);
}

int main(int argc, char **argv)
{
	printf("argc: %d\n", argc);
	mpx_prepare();
	srandom(11179);

	bd_incore();
	init();
	bd_incore();

	xsave_state((void *)xsave_test_buf, 0x1f);
	if (!compare_context(xsave_test_buf))
		printf("Init failed\n");

	if (argc >= 2 && !strcmp(argv[1], "unmaptest")) {
		check_bounds_table_frees();
		printf("done with malloc() fun\n");
	}
	if ((argc < 2) ||
	    (argc >= 2 && !strcmp(argv[1], "tabletest"))) {
		int i;
		for (i = 0; i < 20000; i++)
			check_mpx_insns_and_tables();
	}
	//sleep(560);
	exit(0);
}


