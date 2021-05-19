#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>

extern long asm_syscall(int no, ...);
extern char *readbanner;
extern char *writebanner;

int int2string(int val, char *result) {
	int cur = 0;
	while(val) {
		int t = val % 10;
		result[0x18-cur] = '0' + t;
		val /= 10;
		cur++;
	}
	return cur;
}

void sandbox(){
	int status;
	struct user_regs_struct regs;
	struct timeval tv;
	char filename[0x20] = {0};
	int fd, start;
	long info;
	pid_t pid = asm_syscall(SYS_fork);

	if (!pid){
		asm_syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
		asm_syscall(SYS_kill, asm_syscall(SYS_getpid), SIGCONT);
		return;
	}
	asm_syscall(SYS_gettimeofday, &tv, NULL);
	start = int2string(tv.tv_sec, filename);
	fd = asm_syscall(SYS_open, filename + 0x18 - start + 1, O_RDWR | O_CREAT);
	asm_syscall(SYS_wait4, pid, &status, 0, NULL);
	while(WIFSTOPPED(status)) {
		asm_syscall(SYS_ptrace, PTRACE_SYSCALL, pid, 0, 0);
		asm_syscall(SYS_wait4, pid, &status, 0, NULL);
		asm_syscall(SYS_ptrace, PTRACE_GETREGS, pid, 0, &regs);
		char buf[0x2000];
		void *buf_addr;
		if(regs.orig_rax == SYS_open || \
			regs.orig_rax == SYS_fork || \
			regs.orig_rax == SYS_clone || \
			regs.orig_rax == SYS_vfork || \
			regs.orig_rax == SYS_execve) {
				regs.orig_rax = SYS_exit_group;
				regs.rdi = 0;
				asm_syscall(SYS_ptrace, PTRACE_SETREGS, pid, 0, &regs);
				asm_syscall(SYS_close, fd);
				asm_syscall(SYS_exit, 0);
		}
		else if(regs.orig_rax == SYS_read || regs.orig_rax == SYS_write){
			buf_addr = (void *)regs.rsi;
			asm_syscall(SYS_ptrace, PTRACE_SYSCALL, pid, 0, 0);
			asm_syscall(SYS_wait4, pid, &status, 0, NULL);
			asm_syscall(SYS_ptrace, PTRACE_GETREGS, pid, 0, &regs);

			if (regs.orig_rax==SYS_read) {
				asm_syscall(SYS_write, fd, &readbanner, 7);
			}
			else {
				asm_syscall(SYS_write, fd, &writebanner, 8);
			}

			if (regs.rax > 0){
				for(int i = 0; i < regs.rax; i++) {
					asm_syscall(SYS_ptrace, PTRACE_PEEKDATA, pid, (void*)((unsigned long long)buf_addr + i), &info);
					buf[i] = (char)info;
				}
				buf[regs.rax] = '\n';
				asm_syscall(SYS_write, fd, buf, regs.rax + 1);
			}
		}
		
	}
	asm_syscall(SYS_close, fd);
	asm_syscall(SYS_exit, 0);
}
