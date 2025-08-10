---
title: "CryptoCTF 2025"
date: 2025-08-10T12:00:00+08:00
description: "contributed basically nothing ^_^"
categories: CTF
---

played with NullCipher and got 23rd\
only solved baby challs cause i was busy lololol

# Interpol
source:
```py {hl_lines=[6,7,8,9,10]}
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def randpos(n):
    if randint(0, 1):
        return True, [(-(1 + (19*n - 14) % len(flag)), ord(flag[(63 * n - 40) % len(flag)]))]
    else:
        return False, [(randint(0, 313), (-1) ** randint(0, 1) * Rational(str(getPrime(32)) + '/' + str(getPrime(32))))]

c, n, DATA = 0, 0, []
while True:
    _b, _d = randpos(n)
    H = [d[0] for d in DATA]
    if _b:
        n += 1
        DATA += _d
    else:
        if _d[0][0] in H: continue
        else:
            DATA += _d
            c += 1
    if n >= len(flag): break

A = [DATA[_][0] for _ in range(len(DATA))]
poly = QQ['x'].lagrange_polynomial(DATA).dumps()
f = open('output.raw', 'wb')
f.write(poly)
f.close()
```
the `randpos` function stands out the most, so lets analyze it\
it basically flips a coin and does one of the following:
- a good coord leaking 1 char at random index from our flag `(-some index, ord(flag[another index]))`
- a bad coord that we dont need `(+???, ???)`\
we can differentiate good and bad coords trivially by checking if x is negative!

but first, we need to reverse the lagrange polynomial back to coords\
since they're all small positive integers, we can just brute:
```py
from sage.all import *

with open('output.raw', 'rb') as f:
    poly = loads(f.read())

flag = ''
for x in range(0, -100, -1):
    y = poly(x)
    if y in range(32, 127):
        flag += chr(int(y))

print(flag)
```
which gives
```
eai_AC{_nCl401TZM39_F30}Oni4n!!hrLTc1!pRtn!nr70aCItn_
```
next we have to reverse the repermutation logic! ...or not. apparently i thought trial and error was a good idea

lets observe the order when flag is `abcde`, with their respective index of flag:
```
x = -2, y = 0
x = -1, y = 3
x = -5, y = 1
x = -4, y = 4
x = -3, y = 2
[(-2, 97), (-1, 100), (-5, 98), (-4, 101), (-3, 99)]
```
we can see that if we sort by y, and get the char with the corresponding x coord, we will recover `abcde`\
let's apply that on our ciphertext!
```py
from sage.all import *

with open('output.raw', 'rb') as f:
    poly = loads(f.read())

#Note: we know that flag is 53 chars long by amount of valid coords
coords={}
for x in range(0, -100, -1):
    y = poly(x)
    if y in range(32, 127):
        coords[x]=chr(y)

asdf=[]
for j in range(0, 53):
    new_x = -(1 + (19*j - 14) % 53)
    asdf.append(new_x)
    
decode_perm=[-1] * 53
for j in range(0, 53):
    new_y = (63 * j - 40) % 53
    decode_perm[new_y] = asdf[j]

print(''.join(coords[decode_perm[i]] for i in range(53)))
```
flag: **`CCTF{7h3_!nTeRn4t10naL_Cr!Min41_pOlIc3_0r9An!Zati0n!}`**

# Vainrat
source:
```py
#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from flag import flag

def die(*args):
    pr(*args)
    quit()

def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def sc(): 
    return sys.stdin.buffer.readline()

nbit = 110
prec = 4 * nbit
R = RealField(prec)

def rat(x, y):
    x = R(x + y) * R(0.5)  # x1 = (x0 + y0) / 2
    y = R((x * y) ** 0.5)  # y1 = sqrt(x1 * y0)
    return x, y

def main():
    border = "┃"
    pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    pr(border, ".::               Welcome to Vain Rat challenge!              ::. ", border)
    pr(border, " You should chase the vain rat and catch it to obtain the flag!   ", border)
    pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    m = bytes_to_long(flag)
    x0 = R(10 ** (-len(str(m))) * m)
    while True:
        y0 = abs(R.random_element())
        if y0 > x0: break
    assert len(str(x0)) == len(str(y0))
    c = 0
    pr(border, f'We know y0 = {y0}')
    while True:
        pr("| Options: \n|\t[C]atch the rat \n|\t[Q]uit")
        ans = sc().decode().strip().lower()
        if ans == 'c':
            x, y = rat(x0, y0)
            x0, y0 = x, y
            c += 1
            if c <= randint(12, 19):
                pr(border, f'Unfortunately, the rat got away :-(')
            else: pr(border, f'y = {y}')
        elif ans == 'q': die(border, "Quitting...")
        else: die(border, "Bye...")

if __name__ == '__main__':
    main()
```
starting from \((x_0, y_0)\), the rat's coord undergoes the `rat(x,y)` transformation and jumps to \((x_1, y_1)\), that is:

$$
\begin{aligned}
m &= \text{bytes\_to\_long(flag)} \\
x_0 &= 10^{-\text{len(str(m))}\ \cdot\ m} \\
y_0 &= \text{random} \\
x_1 &= \frac{x_0 + y_0}{2} \\
y_1 &= \sqrt{x_1 + y_0} \\
\end{aligned}
$$
next you'll need divine intervention and come to a conclusion that \( x_1^2 - y_1^2 \) is useful:

$$
\begin{aligned}
x_1^2 - y_1^2 &= \frac{x_0^2 + y_0^2}{4} \newline
\text{thus}\ x_n^2 - y_n^2 &= \frac{x_0^2 + y_0^2}{4^n}
\end{aligned}
$$
since we have \(y_0\), we can recover \(x_0\)!

$$
\begin{aligned}
x_0 = \sqrt{4^n(x_n^2 - y_n^2) - y_0^2}
\end{aligned}
$$
finally we can recover `m` by bruting for the flag's length, and with a little gambling we can recover the flag!

solve script by `@killua4564`:
```py
from Crypto.Util.number import long_to_bytes
from pwn import remote
from sage.all import RealField, sqrt

c = 20
prec = 440
R = RealField(prec)

conn = remote("91.107.252.0", "11117")
conn.recvuntil(b"We know y0 = ")
y0 = R(conn.recvuntil(b"\n").strip().decode())

for _ in range(c-1):
    conn.sendlineafter(b"[Q]uit", b"C")

conn.sendlineafter(b"[Q]uit", b"C")
conn.recvuntil(b"y = ")
yc0 = R(conn.recvuntil(b"\n").strip().decode())

conn.sendlineafter(b"[Q]uit", b"C")
conn.recvuntil(b"y = ")
yc1 = R(conn.recvuntil(b"\n").strip().decode())

xc0 = R(2) * yc1 ** 2 / yc0 - yc0
x0 = ((xc0 ** 2 - yc0 ** 2) * R(4) ** c + y0 ** 2) ** R(0.5)

# xc1 = yc1 ** 2 / yc0
# x0_squared = ((xc1 ** 2 - yc1 ** 2) * R(4) ** (c + 1) + y0 ** 2) ** R(0.5)

for k in range(1, prec):
    flag = long_to_bytes(int(x0 * R(10) ** k))
    if flag.startswith(b"CCTF{"):
        print(flag.decode())
```
flag: **`CCTF{h3Ur1s7!c5_anD_iNv4rIanTs_iN_CryptoCTF_2025!}`**