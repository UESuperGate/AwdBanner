#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

void sandbox(){
	int status;
	struct user_regs_struct regs;
	pid_t pid = fork();
	if (pid < 0) {
		printf("server init failed!\n");
		exit(1);
	}

	if (!pid){
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGCONT);
		return;
	}

	waitpid(pid, &status, 0);
	while(WIFSTOPPED(status)) {
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, &status, 0);
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		printf("syscall:%d\n", regs.orig_rax);

		if(regs.orig_rax == SYS_open || \
			regs.orig_rax == SYS_fork || \
			regs.orig_rax == SYS_clone || \
			regs.orig_rax == SYS_vfork) {
				regs.orig_rax = SYS_exit_group;
				regs.rdi = 0;
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
				puts("execve syscall detected!");
				exit(0);
			}
		}
}

int main() {
	sandbox();

	// system("ls");
	open("fuc");
	printf("\n");
	return 0;
}
