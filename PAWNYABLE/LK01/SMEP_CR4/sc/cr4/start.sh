qemu-system-x86_64 \
-m 512M \
-kernel ./bzImage \
-initrd ./rootfs_updated.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet nokaslr" \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
-cpu qemu64,smep \
-no-reboot \
-gdb tcp::12345
