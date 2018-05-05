/*
 * Copyright (C) 2007-2010 Stealth.
 * All rights reserved.
 *
 * This is NOT a common BSD license, so read on.
 *
 * Redistribution in source and use in binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. The provided software is FOR EDUCATIONAL PURPOSES ONLY! You must not
 *    use this software or parts of it to commit crime or any illegal
 *    activities. Local law may forbid usage or redistribution of this
 *    software in your country.
 * 2. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 3. Redistribution in binary form is not allowed.
 * 4. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Stealth.
 * 5. The name Stealth may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <dlfcn.h>


#ifdef __x86_64__
#define elf_auxv_t Elf64_auxv_t
#else
#define elf_auxv_t Elf32_auxv_t
#endif

#ifndef AT_RANDOM
#define AT_RANDOM 25
#endif
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif


struct process_hook {
	pid_t pid;
	char *dso;
	void *dlopen_address;
} process_hook = {0, NULL, NULL};


void die(const char *s)
{
	perror(s);
	exit(errno);
}


void show_auxv(const char *pid)
{
	char buf[1024];
	int fd = -1;
	ssize_t r = 0;
	elf_auxv_t *auxv = NULL;

	snprintf(buf, sizeof(buf), "/proc/%s/auxv", pid);

	if ((fd = open(buf, O_RDONLY)) < 0)
		die("[-] open");

	if ((r = read(fd, buf, sizeof(buf))) < 0)
		die("[-] read");
	close(fd);

	for (auxv = (elf_auxv_t *)buf; auxv->a_type != AT_NULL && (char *)auxv < buf + r; ++auxv) {
		switch (auxv->a_type) {
		case AT_IGNORE:
			printf("AT_IGNORE\n");
			break;
		case AT_EXECFD:
			printf("AT_EXECFD:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PHDR:
			printf("AT_PHDR:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_PHENT:
			printf("AT_PHENT:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PHNUM:
			printf("AT_PHNUM:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PAGESZ:
			printf("AT_PAGESZ:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_BASE:
			printf("AT_BASE:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_FLAGS:
			printf("AT_FLAGS:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_ENTRY:
			printf("AT_ENTRY:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_UID:
			printf("AT_UID:\t\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_EUID:
			printf("AT_EUID:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_GID:
			printf("AT_GID:\t\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_EGID:
			printf("AT_EGID:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_CLKTCK:
			printf("AT_CLKTCK:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_PLATFORM:
			printf("AT_PLATFORM:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_HWCAP:
			printf("AT_HWCAP:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_FPUCW:
			printf("AT_FPUCW:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_DCACHEBSIZE:
			printf("AT_DCACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_ICACHEBSIZE:
			printf("AT_ICACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_UCACHEBSIZE:
			printf("AT_UCACHEBSIZE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_SECURE:
			printf("AT_SECURE:\t%zd\n", auxv->a_un.a_val);
			break;
		case AT_SYSINFO:
			printf("AT_SYSINFO:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_SYSINFO_EHDR:
			printf("AT_SYSINFO_EHDR:%p\n", (void *)auxv->a_un.a_val);
			break;
		case AT_RANDOM:
			printf("AT_RANDOM:\t0x%zx\n", auxv->a_un.a_val);
			break;
		case AT_EXECFN:
			printf("AT_EXECFN:\t%p\n", (void *)auxv->a_un.a_val);
			break;
		default:
			printf("AT_UNKNOWN(%zd):\t0x%zx\n", auxv->a_type, auxv->a_un.a_val);
		}
	}
}


size_t at_base(pid_t pid)
{
	char buf[1024];
	int fd = -1;
	ssize_t r = 0;
	elf_auxv_t *auxv = NULL;

	snprintf(buf, sizeof(buf), "/proc/%d/auxv", pid);

	if ((fd = open(buf, O_RDONLY)) < 0)
		die("[-] open");

	if ((r = read(fd, buf, sizeof(buf))) < 0)
		die("[-] read");
	close(fd);

	for (auxv = (elf_auxv_t *)buf; auxv->a_type != AT_NULL && (char *)auxv < buf + r; ++auxv) {
		if (auxv->a_type == AT_BASE)
			return auxv->a_un.a_val;
	}
	return 0;
}


char *find_libc_start(pid_t pid)
{
	char path[1024];
	char buf[1024], *start = NULL, *end = NULL, *p = NULL;
	char *addr1 = NULL, *addr2 = NULL;
	FILE *f = NULL;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);

	if ((f = fopen(path, "r")) == NULL)
		die("[-] fopen");

	for (;;) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (!strstr(buf, "r-xp"))
			continue;
		if (!(p = strstr(buf, "/")))
			continue;
		if ((!strstr(p, "/lib64/") && !strstr(p, "/lib/")) || !strstr(p, "/libc-"))
			continue;
		start = strtok(buf, "-");
		addr1 = (char *)strtoul(start, NULL, 16);
		end = strtok(NULL, " ");
		addr2 = (char *)strtoul(end, NULL, 16);
		break;
	}

	fclose(f);
	return addr1;
}


int poke_text(pid_t pid, size_t addr, void *buf, size_t blen)
{
	int i = 0;
	char *ptr = (char *)malloc(blen + blen % sizeof(size_t));	// word align
	memcpy(ptr, buf, blen);

	for (i = 0; i < blen; i += sizeof(size_t)) {
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, *(size_t *)&ptr[i]) < 0)
			die("[-] ptrace");
	}
	free(ptr);
	return 0;
}



int peek_text(pid_t pid, size_t addr, char *buf, size_t blen)
{
	int i = 0;
	size_t word = 0;
	for (i = 0; i < blen; i += sizeof(size_t)) {
		word = ptrace(PTRACE_PEEKTEXT,pid, addr + i, NULL);
		memcpy(&buf[i], &word, sizeof(word));
	}
	return 0;
}

#ifdef __x86_64__
/* from linux/user.h which disappeared recently: */
struct my_user_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
/* arguments: non interrupts/non tracing syscalls only save upto here*/
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
/* end of arguments */
/* cpu exception frame or undefined */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};


int inject_code(const struct process_hook *ph)
{
	char sbuf1[1024], sbuf2[1024];
	struct my_user_regs regs, saved_regs, aregs;
	int status;
	size_t v = 0;

	assert(ph);

	printf("[+] 64bit mode\n");

	if (ptrace(PTRACE_ATTACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");
	waitpid(ph->pid, &status, 0);
	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace");

	peek_text(ph->pid, regs.rsp + 1024, sbuf1, sizeof(sbuf1));
	peek_text(ph->pid, regs.rsp, sbuf2, sizeof(sbuf2));

	/* fake saved return address, triggering a SIGSEGV to catch */
	v = 0;
	poke_text(ph->pid, regs.rsp, (char *)&v, sizeof(v));
	poke_text(ph->pid, regs.rsp + 1024, ph->dso, strlen(ph->dso) + 1);

	memcpy(&saved_regs, &regs, sizeof(regs));
	printf("[+] rdi=0x%zx rsp=0x%zx rip=0x%zx\n", regs.rdi, regs.rsp, regs.rip);

	/* arguments to function we call */
	regs.rdi = regs.rsp + 1024;
	regs.rsi = RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE;
	regs.rip = (size_t)ph->dlopen_address + 2;// kernel bug?! always need to add 2!

	if (ptrace(PTRACE_SETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace");
	if (ptrace(PTRACE_CONT, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");
	/* Should receive a SIGSEGV for return to 0 */
	waitpid(ph->pid, &status, 0);

	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &aregs) < 0)
		die("[-] ptrace");

	printf("[+] rdi=0x%zx rsp=0x%zx rip=0x%zx\n", aregs.rdi, aregs.rsp, aregs.rip);
	if (ptrace(PTRACE_SETREGS, ph->pid, 0, &saved_regs) < 0)
		die("[-] ptrace");

	poke_text(ph->pid, saved_regs.rsp + 1024, sbuf1, sizeof(sbuf1));
	poke_text(ph->pid, saved_regs.rsp, sbuf2, sizeof(sbuf2));

	if (ptrace(PTRACE_DETACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");
	if (aregs.rip != 0)
		printf("[-] dlopen in target may have failed (no clean NULL fault)\n");

	return 0;
}

#else

struct my_user_regs {
	uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
	unsigned short ds, __ds, es, __es;
	unsigned short fs, __fs, gs, __gs;
	uint32_t orig_eax, eip;
	unsigned short cs, __cs;
	uint32_t eflags, esp;
	unsigned short ss, __ss;
};


int inject_code(const struct process_hook *ph)
{
	char sbuf1[1024], sbuf2[1024];
	struct my_user_regs regs, saved_regs, aregs;
	int status;
	size_t v = 0;

	assert(ph);

	printf("[+] 32bit mode\n");

	if (ptrace(PTRACE_ATTACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");
	waitpid(ph->pid, &status, 0);
	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace");

	peek_text(ph->pid, regs.esp + 1024, sbuf1, sizeof(sbuf1));
	peek_text(ph->pid, regs.esp, sbuf2, sizeof(sbuf2));

	/* fake saved return address, triggering a SIGSEGV to catch */
	v = 0x0;
	poke_text(ph->pid, regs.esp, (char *)&v, sizeof(v));
	poke_text(ph->pid, regs.esp + 1024, ph->dso, strlen(ph->dso) + 1); 

	memcpy(&saved_regs, &regs, sizeof(regs));

	printf("[+] esp=0x%zx eip=0x%zx\n", regs.esp, regs.eip);

	/* arguments passed on stack this time (x86) */
	v = regs.esp + 1024;
	poke_text(ph->pid, regs.esp + sizeof(size_t), &v, sizeof(v));
	v = RTLD_NOW|RTLD_GLOBAL|RTLD_NODELETE;
	poke_text(ph->pid, regs.esp + 2*sizeof(size_t), &v, sizeof(v));

	/* kernel bug. always add 2; in -m32 mode on 64bit systems its
	 * not needed!!!
	 */
	regs.eip = (size_t)ph->dlopen_address + 2;

	if (ptrace(PTRACE_SETREGS, ph->pid, NULL, &regs) < 0)
		die("[-] ptrace");
	if (ptrace(PTRACE_CONT, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");

	/* Should receive a SIGSEGV for return to 0 */
	waitpid(ph->pid, &status, 0);

	if (ptrace(PTRACE_GETREGS, ph->pid, NULL, &aregs) < 0)
		die("[-] ptrace");

	printf("[+] esp=0x%zx eip=0x%zx\n", aregs.esp, aregs.eip);

	if (ptrace(PTRACE_SETREGS, ph->pid, 0, &saved_regs) < 0)
		die("[-] ptrace");

	poke_text(ph->pid, saved_regs.esp + 1024, sbuf1, sizeof(sbuf1));
	poke_text(ph->pid, saved_regs.esp, sbuf2, sizeof(sbuf2));

	if (ptrace(PTRACE_DETACH, ph->pid, NULL, NULL) < 0)
		die("[-] ptrace");
	if (aregs.eip != 0)
		printf("[-] dlopen in target may have failed (no clean NULL fault)\n");

	return 0;
}
#endif

void usage(const char *path)
{
	printf("Usage: %s <-p pid> <-P dso-path> [-s pid]\n", path);
	exit(1);
}


/* The easy way to calculate address of target symbol
 */
void fill_offsets_maps(struct process_hook *ph)
{
	char *my_libc = NULL, *daemon_libc = NULL;
	int32_t dlopen_offset = 0;
	char *dlopen_mode = NULL;

	assert(ph);

	printf("[+] Using /proc/pid/maps method ...\n");
	my_libc = find_libc_start(getpid());
	if (!my_libc) {
		printf("[-] Unable to locate my own libc.\n");
		return;
	}

	dlopen_mode = dlsym(NULL, "__libc_dlopen_mode");
	if (dlopen_mode)
		printf("[+] My __libc_dlopen_mode: %p\n", dlopen_mode);
	else {
		printf("[-] Unable to locate my own dlopen address.\n");
		return;
	}

	dlopen_offset = dlopen_mode - my_libc;
	daemon_libc = find_libc_start(ph->pid);
	if (!daemon_libc) {
		printf("[-] Unable to locate target's libc.\n");
		return;
	}
	printf("[+] Foreign libc start: %p\n", daemon_libc);
	ph->dlopen_address = daemon_libc + dlopen_offset;
}


/* Got how this works? :)
 * Since we link against libdl, we also need a lib_diff
 * (target may lack this mapping). Otherwise we could just
 * add the static offset between AT_BASE and __libc_dlopen_mode.
 * We use ldd. The good thing about this is, we do not
 * need ptrace() and no /proc/pid/maps to find our target symbol.
 */
void fill_offsets_auxv(struct process_hook *ph)
{
	FILE *pfd = NULL;
	char *dlopen_mode = NULL;
	int32_t dlopen_offset = 0, lib_diff = 0;
	size_t my_base = 0, daemon_base = 0;
	char buf[1024+24], proc1[1024], proc2[1024];
	size_t libc_a = 0, ld_a = 0, libc_a_ = 0, ld_a_ = 0;

	assert(ph);

	printf("[+] Using AT_BASE method ...\n");
	my_base = at_base(getpid());
	if (!my_base) {
		printf("[-] Unable to locate my own AT_BASE.\n");
		return;
	}

	printf("[+] My AT_BASE: 0x%zx\n", my_base);
	dlopen_mode = dlsym(NULL, "__libc_dlopen_mode");
	if (dlopen_mode)
		printf("[+] My __libc_dlopen_mode: %p\n", dlopen_mode);
	else {
		printf("[-] Unable to locate my own dlopen address.\n");
		return;
	}

	dlopen_offset = (size_t)dlopen_mode - my_base;
	daemon_base = at_base(ph->pid);
	if (!daemon_base) {
		printf("[-] Unable to locate target's AT_BASE.\n");
		return;
	}
	printf("[+] Foreign AT_BASE: 0x%zx\n", daemon_base);

	memset(proc1, 0, sizeof(proc1));
	if (readlink("/proc/self/exe", proc1, sizeof(proc1)) < 0) {
		printf("[-] Unable to resolve my own path.\n");
		return;
	}
	memset(proc2, 0, sizeof(proc2));
	snprintf(buf, sizeof(buf), "/proc/%d/exe", ph->pid);
	if (readlink(buf, proc2, sizeof(proc2)) < 0) {
		printf("[-] Unable to resolve target path.\n");
		return;
	}

	/* shell escapes in exe link are unimportant here */
	snprintf(buf, sizeof(buf), "ldd %s", proc1);
	pfd = popen(buf, "r");
	do {
		if (!fgets(buf, sizeof(buf), pfd))
			break;
		sscanf(buf, "%*255[^l]libc%*255[^(](%zx)", &libc_a);
		sscanf(buf, "%*255[^-]-linux%*255[^(](%zx)", &ld_a);
	} while ((libc_a == 0 || ld_a == 0) && !feof(pfd));
	pclose(pfd);

	if (libc_a == 0 || ld_a == 0) {
		printf("[-] Unable to determine lib difference (me).\n");
		return;
	}
	snprintf(buf, sizeof(buf), "ldd %s", proc2);
	pfd = popen(buf, "r");
	do {
		if (!fgets(buf, sizeof(buf), pfd))
			break;
		sscanf(buf, "%*255[^l]libc%*255[^(](%zx)", &libc_a_);
		sscanf(buf, "%*255[^-]-linux%*255[^(](%zx)", &ld_a_);
	} while ((libc_a_ == 0 || ld_a_ == 0) && !feof(pfd));
	pclose(pfd);

	if (libc_a_ == 0 || ld_a_ == 0) {
		printf("[-] Unable to determine lib difference (target).\n");
		return;
	}
	lib_diff = ld_a - libc_a - (ld_a_ - libc_a_);
	printf("[+] lib diff: %d (0x%x)\n", lib_diff, lib_diff);
	ph->dlopen_address = (void *)(daemon_base + dlopen_offset + lib_diff);
}


/* The last chance if nothing above worked */
void fill_offsets_nm(struct process_hook *ph)
{
	FILE *pfd = NULL;
	char buf[128], *space = NULL, *daemon_libc = NULL;
	size_t dlopen_offset = 0;

	assert(ph);

	printf("[+] Using nm method ...\n");
	daemon_libc = find_libc_start(ph->pid);
	if (!daemon_libc) {
		printf("[-] Unable to locate foreign libc.\n");
		return;
	}

	memset(buf, 0, sizeof(buf));
	if (((pfd = popen("nm /lib64/libc.so.6|grep __libc_dlopen_mode", "r")) != NULL ||
	     (pfd = popen("nm /lib/libc.so.6|grep __libc_dlopen_mode", "r")) != NULL)) {
		/* to make ubuntu's gcc happy! */
		if (!fgets(buf, sizeof(buf), pfd))
			;
		if ((space = strchr(buf, ' ')) != NULL)
			*space = 0;
		dlopen_offset = strtoul(buf, NULL, 16);
		fclose(pfd);
	}
	if (!dlopen_offset) {
		printf("[-] Unable to locate symbol via nm.\n");
		return;
	}
	ph->dlopen_address = daemon_libc + dlopen_offset;
}


int main(int argc, char **argv)
{
	char c;

	while ((c = getopt(argc, argv, "s:p:P:")) != -1) {
		switch (c) {
		case 'P':
			process_hook.dso = realpath(optarg, NULL);
			break;
		case 'p':
			process_hook.pid = atoi(optarg);
			break;
		case 's':
			show_auxv(optarg);
			exit(0);
		default:
			usage(argv[0]);
		}
	}

	setbuffer(stdout, NULL, 0);

	printf("injectso v0.51 -- DSO process hotpatching tool\n\n");
	if (!process_hook.dso || !process_hook.pid) {
		usage(argv[0]);
	}

	if (access(process_hook.dso, R_OK|X_OK) < 0) {
		fprintf(stderr, "[-] DSO is not rx\n");
		return 1;
	}

	fill_offsets_maps(&process_hook);

	if (process_hook.dlopen_address == 0) {
		fill_offsets_auxv(&process_hook);
	}
	if (process_hook.dlopen_address == 0) {
		fill_offsets_nm(&process_hook);
	}
	if (process_hook.dlopen_address == 0) {
		printf("[-] Unable to locate foreign dlopen address.\n");
		return 1;
	}

	printf("[+] => Foreign dlopen address: %p\n", process_hook.dlopen_address);
	printf("[+] Using normalized DSO path '%s'\n", process_hook.dso);
	inject_code(&process_hook);

	printf("[+] done.\n");
	return 0;
}

