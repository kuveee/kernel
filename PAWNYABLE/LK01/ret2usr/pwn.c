#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int global_fd;

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

void read_kn() {
  char buf[100];
  int64_t data = read(global_fd, buf, sizeof(buf));
  printf("data read: %s", buf);
}

void write_kn() {
  char buf[50];
  strcpy(buf, "Hello kernel!!!");
  write(global_fd, buf, 15);
}

int main() {
  open_kn();
  write_kn();
  read_kn();
  return 0;
}