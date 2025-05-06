// tty.h
#ifndef _TTY_H_
#define _TTY_H_

#include <stdint.h>
#include <sys/types.h>

/* forward declare the kernel struct we never really define here */
struct tty_struct;

/*
 * Minimal tty_operations layout:
 *   – 8 pointers of padding (to skip over the real first ops),
 *   – then the ioctl callback we actually overwrite.
 */
struct tty_operations {
  void *pad[8];
  long (*ioctl)(struct tty_struct *tty, unsigned int cmd, unsigned long arg);
};

#endif /* _TTY_H_ */

