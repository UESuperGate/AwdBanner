#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

extern long asm_syscall(int no, ...);

void sandbox(){
	int status;
	struct user_regs_struct regs;
	pid_t pid = asm_syscall(SYS_fork);

	if (!pid){
		// ptrace(PTRACE_TRACEME, 0, 0, 0);
		asm_syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
		asm_syscall(SYS_kill, asm_syscall(SYS_getpid), SIGCONT);
		// raise(SIGCONT);
		return;
	}

	asm_syscall(SYS_wait4, pid, &status, 0, NULL);
	// waitpid(pid, &status, 0);
	while(WIFSTOPPED(status)) {
		// ptrace(PTRACE_SYSCALL, pid, 0, 0);
		asm_syscall(SYS_ptrace, PTRACE_SYSCALL, pid, 0, 0);
		// waitpid(pid, &status, 0);
		asm_syscall(SYS_wait4, pid, &status, 0, NULL);
		// ptrace(PTRACE_GETREGS, pid, 0, &regs);
		asm_syscall(SYS_ptrace, PTRACE_GETREGS, pid, 0, &regs);

		if(regs.orig_rax == SYS_open || \
			regs.orig_rax == SYS_fork || \
			regs.orig_rax == SYS_clone || \
			regs.orig_rax == SYS_vfork || \
			regs.orig_rax == SYS_execve) {
				regs.orig_rax = SYS_exit_group;
				regs.rdi = 0;
				// ptrace(PTRACE_SETREGS, pid, 0, &regs);
				asm_syscall(SYS_ptrace, PTRACE_SETREGS, pid, 0, &regs);
				// asm_syscall(SYS_write, 1, "flag{1l4_514_igI981O_fUck}\n", 0x1a);
				// exit(0);
				asm_syscall(SYS_exit, 0);
		}
	}
	asm_syscall(SYS_exit, 0);
}

// int main() {
// 	sandbox();

// 	system("ls");
// 	printf("\n");
// 	return 0;
// }
