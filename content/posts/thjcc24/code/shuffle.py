f = open("output.txt", "r")

flag = b''
for line in f:
    if flag == b'':
        flag = bytes.fromhex(line)
    else:
        flag = bytes(a ^ b for a, b in zip(flag, bytes.fromhex(line)))
print(flag)

f.close()