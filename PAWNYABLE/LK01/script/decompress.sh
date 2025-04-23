#!/bin/sh

mkdir initramfs
cd initramfs
cp ../initramfs.cpio.gz .
gunzip ./initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio


### 
$ mkdir root
$ cd root; cpio -idv < ../rootfs.cpio
...
$ find . -print0 | cpio -o --format=newc --null --owner=root > ../rootfs_updated.cpio
###
