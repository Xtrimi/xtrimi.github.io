import urllib.parse
import bcrypt

leak = b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'
salt = b'$2b$12$8bMrI6D9TMYXeMv8pq8Rje'
ADMIN_PW_HASH = b'$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK'

for i in range(256):
    guess = bytes([i])
    hashed = bcrypt.hashpw(leak + guess, salt)
    
    print(f'guessing {guess}')
    if hashed == ADMIN_PW_HASH: # found 0xAA
        print(f'found pass: {urllib.parse.quote_from_bytes(leak + guess)}')
        exit()
print('D:')