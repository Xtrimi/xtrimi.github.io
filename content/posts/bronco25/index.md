---
title: "BroncoCTF 2025"
date: 2025-02-19T12:00:00+08:00
description: "i hate steganography with a burning passion"
categories: CTF
---

we got 12th! yay\
prob wouldve gotten higher but the remaining chals are literally just mind reading and i cba\
ill only be explaining chals i care about & all web

# Web
## Grandma's Secret Recipe
we can login as `'kitchen helper'` but we need to access the pantry as `'grandma'`\
checking our cookies we have cookies `checksum` and `role`\
throwing checksum into a hash checker we know its md5, so we can just throw a md5 hash of 'grandma' and edit cookie to get through

## Miku's Autograph
to get the autograph we need to login as `miku_admin`, except we can only login in `miku_user`\
checking source we find two endpoints:
```js
function magicMikuLogin() {
    fetch('/get_token')
    .then(response => response.json())
    .then(data => {
        let token = data.your_token;
        fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'magic_token=' + encodeURIComponent(token)
        })
        .then(response => response.text())
        .then(result => document.body.innerHTML = result);
    });
}
```
requesting /get_token we get a JWT token:
```json
{"your_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtaWt1X3VzZXIiLCJleHAiOjE3Mzk5NTM5NTh9.EyGIQs1I6Qz4SipOarBj6WIhWFfNWkpaNKlyuU3lQU8"}
```
header & payload:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "miku_user",
  "exp": 1739953958
}
```
originally i tried cracking secret, but meanwhile i tried changing algorithm to **'none'**, **appending a dot** and **changing sub to `miku_admin`** and it worked\
which means the server didnt check if algorithm was correct
>  Welcome, Miku Admin! Here's your flag: **`bronco{miku_miku_beaaaaaaaaaaaaaaaaaam!}`**

## Mary's Lamb is a Little Phreak
joke chal lmao\
unminifying frontend script we know our input is POSTed on the /mary/ endpoint
```js
const _m = Y.create({ baseURL: "https://mary.web.broncoctf.xyz", headers: { "Content-type": "application/json", "Access-Control-Allow-Origin": "*" } }),
    Tm = (e) => _m.get(`/${e}`),
    Pm = { getAll: Tm },
    Nm = (e, t) => {
        Pm.getAll(`mary/${e}`)
            .then((r) => (console.log(r), t(r.data.message), r.data))
            .catch((r) => {
                console.log(r);
            });
    },
    Rm = { getMario: Nm };
```
so we just need to find mary has a little lamb song in DTMF (should be in a reddit post): `32123332223993212333322321`

flag: **`bronco{W0ah_y0u_f0und_m4rys_1itt1e_1amb}`**

# Forensics
## Bucky's Impossible Obby
> Bucky swears this obby is IMPOSSIBLE. But he also says his obby has a flag for us in an alternate universe. What gives?

editing the [given uncopylocked place](www.roblox.com/games/131965012415321) we see a GUI with this text inside it:
> (dev note #878: still deciding on the flag, **test**ing some options before i ship it to this **place**)

since this was the only place in the game's universe (and no other term in roblox along the name of "testplace") i turned to the creator's places in inventory\
which i found [bucky obby test place](www.roblox.com/games/115403792174655)
and in the same gui we find LocalScript that invokes FlagCaller in server script service:
```lua
local b = require(132906055852488)

game.ReplicatedStorage.GetFlag.OnServerInvoke = function()
    return b.flaggyflagflags()
end
```
the fact this script is functional implies the model associated with the ID is public! lets [check it out](https://create.roblox.com/store/asset/132906055852488)\
the model contains MainModule:
```lua
local buckysSuperAmazingFlagModule = {}
function buckysSuperAmazingFlagModule.flaggyflagflags() 

    -- hey you!
    -- yeah you!
    -- stop snooping around!
    -- there's nothing to see here! 

    -- ( - v - ) . z Z


    -- ( o - o )

    -- i'm his assistant!
    -- let's take a tour of this amazing module
    -- while he's asleep.

    -- important data!
    local data = {
        var_0107 = "_is_one_",
        var_0113 = "percent_",
        var_0103 = "his_flag",
        var_0011 = "11_w0w!}",
        var_0127 = "wrong_sr",
        var_0109 = "hundred_",
        var_0005 = "p0551bl3",
        var_0003 = "0t_s0_1m",
        var_0101 = "Boncoo{T",
        var_0002 = "bronco{n",
        var_0007 = "_4ft3r_4",
        var_0131 = "ry_mate}",
    }    

    -- helper function
    local function ip(n)
        if n <= 1 then
            return false
        end
        for i = 2, math.sqrt(n) do
            if n % i == 0 then
                return false
            end
        end
        return true
    end
    -- helper function
    local ps = {}
    local n = 100
    local lim = 7
    while #ps < lim do
        if ip(n) then
            table.insert(ps, n)
        end
        n = n + 1
    end
    -- where the flag magic happens
    local flag = ""
    for i, p in pairs(ps) do
        flag = flag .. data["var_" .. string.format("%04d", tostring(p))]
    end

    -- and there you go!
    return flag
end
return buckysSuperAmazingFlagModule
```
you can reconstruct the flag by juts swapping around `data` table, or you can just examine a bit and realize it just takes prime numbered variables!
flag prefix `bronco{n` is at var_0002, so we'll set n = 0
but then data[var_00XX] could be nil, so we'll add a check:
```lua
if data["var_" .. string.format("%04d", tostring(p))] == nil then
    continue
end
```
running the script we get the flag: **`bronco{n0t_s0_1mp0551bl3_4ft3r_411_w0w!}`**


# Misc
## World's Hardester Flag
> Just like before, touch the WinPad in the new course and a popup will appear with the flag. Intentionally given access to a semi-restricted terminal, you must do whatever it takes to get the flag with the game in its current form.

initially the teleporters weren't working, which surprisingly had an easier solve path:
### brainless solving
firstly we need to know whats in [the game](www.roblox.com/games/97958089823595)\
some strings are banned, but we can use string concatenation to get around:
```lua
for _, v in pairs(game:GetDescendants()) do
    print(v["Na".."me"])
end
```
checking F9 console i noticed the following:
```
19:09:27 -- Win
19:09:27 -- WinnerPopup
19:09:27 -- Flag
19:09:27 -- WinnerTitle
```
this looks like gui elements! checking its ClassName we can confirm `Flag` is a textlabel:
```lua
for _, v in pairs(game:GetDescendants()) do
    if v["Na".."me"] == "Flag" then
        print(v["ClassNa".."me"]) --TextLabel
    end
end
```
now just print the text property and win!
```lua
for _, v in pairs(game:GetDescendants()) do
    if v["Na".."me"] == "Flag" then
        print(v.Text) -- bronco{n0th1ng_1s_2oo_h4rd_4_m3!}
    end
end
```
### actual solve (a.k.a even more cheeses)
what if we never use the banned words?
> [BANS] !!! BANNED WORDS BY DEHMASTER: **`position, humanoid, destroy, name`**. !!!

the challenge is still super solvable! and i can show 3 more solutions

1. one thing to know is that :Destroy() involves setting the object's parent to nil, and it isn't blocked here\
so just poof every blue thing out!
```lua
for _, v in pairs(game:GetDescendants()) do
    if v.Color == Color3.new(0, 0, 1) then
        v.Parent = nil
    end
end
```
however despite using this the coin door is still broken as of writing?

2. since :PivotTo() (and the deprecated :SetPrimaryPartCFrame()) also exists on models, we can cheese the banned Position by that too, effectively tp-ing anywhere
3. who said we need to do the level? make floors big and walls small\
demonstrating using level H:
```lua
workspace.Levels.Demo.H.Level.BottomWall.Size = Vector3.new(0.01, 0.01, 0.01)
workspace.Levels.Demo.H.Level.H.Floor = Vector3.new(2048, 1, 2048)
```

flag: **`bronco{n0th1ng_1s_2oo_h4rd_4_m3!}`**