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

	if (!pid){
		ptrace(PTRACE_TRACEME, 0, 0, 0);
		raise(SIGCONT);
		return;
	}

	waitpid(pid, &status, 0);
	while(WIFSTOPPED(status)){
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, &status, 0);
		ptrace(PTRACE_GETREGS, pid, 0, &regs);

		char buf[0x1024];
		void *buf_addr;
		if(regs.orig_rax == SYS_execve || \
			regs.orig_rax == SYS_fork || \
			regs.orig_rax == SYS_clone || \
			regs.orig_rax == SYS_vfork) {
				regs.orig_rax = SYS_exit_group;
				regs.rdi = 0;
				ptrace(PTRACE_SETREGS, pid, 0, &regs);
				puts("execve syscall detected!");
				exit(0);
		}
		else if(regs.orig_rax == SYS_read || regs.orig_rax == SYS_write){
			// char byte;
			buf_addr = (void *)regs.rsi;

			ptrace(PTRACE_SYSCALL, pid, 0, 0);
			waitpid(pid, &status, 0);
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			printf("rax: %llx\n", regs.rax);

			if(regs.rax <= 0)
				printf("no buffer %s", regs.orig_rax==SYS_read?"read":"write");
			else{
				for(int i = 0; i < regs.rax; i++)
					buf[i] = (char)ptrace(PTRACE_PEEKDATA, pid, (void*)((unsigned long long)buf_addr + i));
				buf[regs.rax] = 0;
				printf("%s buf: %s\n", regs.orig_rax==SYS_read?"received":"sent", buf);
			}
		}
		
	}
	exit(0);
}

char buf[1024] = "1145141919810";

int main(){
	sandbox();

	read(0, buf, sizeof(buf));
	read(0, buf, sizeof(buf));
	puts("fuckyou1");
	write(1, "fuckyou2\n", 0xa);


	system("ls");
	return 0;
}
