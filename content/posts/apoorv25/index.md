---
title: "apoorvctf 2025 writeup draft"
date: 2025-03-03T00:00:00+08:00
description: "lol"
categories: CTF
---

# SEO CEO
## overview
i dived through the nextjs script and found nothing of importance, so i turned to **basic information leak**(.htaccess, .DS_Store etc.)\
we also have to take in account the chall title mentions SEO, thus **robots.txt and sitemap.xml** came to mind\
robots.txt does exist but was clearly a fake flag, but in sitemap.xml we see an interesting route:
```
<url>
<loc>https://www.thiswebsite.com/goofyahhroute</loc>
<lastmod>2025-02-26</lastmod>
<changefreq>never</changefreq>
<priority>0.0</priority>
</url>
```
going to https://seo-opal.vercel.app/goofyahhroute we see:
> ok bro u da seo master gng frfr ngl no cap
> but do you really want the **"flag"**?
> come on blud, it's a yes or no question
> yeah?
> 
> tell it to the **url** then blud

either querying with ?flag=true and ?flag=yes gives us our flag: **`apoorvctf{s30_1snT_0pt1onaL}`**

# Blog-1
## analysis
we are given a blog posting website in which we need an account to do so, upon login we are told theres a reward once we've made 5 posts\
however we can't make more than 1 posts, as its limited to 1 per day
## solving
if we check our addBlog requests, we will see theres a field named `date`\
but upon forging the date we can clearly see the date doesnt matter, as **the date is handled server side** (but the server side does check if the date field exists)\
then i was stuck on this for a while, after doing basic sql injection & jwt stuff i abandoned this chall

but then my teammate suggested **race condition**, it was then i realized the processing time for creating a post was suspiciously slow for the operation (~10 seconds)\
so then i tried to spam post creating before the server has time to increment my post count
```js
for (var i = 0; i < 10; i++) {
    fetch('http://chals1.apoorvctf.xyz:5001/api/v1/blog/addBlog', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem("token")}`
        },
        body: JSON.stringify({
            title: "fsdgsd",
            description: "sdgg",
            visible: true,
            date: "2025-03-01T08:29:00.725Z"
        })
    })
}
```
then the rest is just gambling i cant repro this as of now so lol

after we check daily rewards we are greeted with A SKIBIDI TOILET VIDEO WTF\
however if you see the request very closely:\
`http://chals1.apoorvctf.xyz:5001/api/v2/gift`\
**we are sending to the v2 api, but all the other requests are to v1 api,** which is sus af\
changing v2 to v1: `http://chals1.apoorvctf.xyz:5001/api/v1/gift` we are then greeted with the flag **`apoorvctf{s1gm@_s1gm@_b0y}`**

# ArchBTW
## analysis
we are given synoonyms.txt, flag.txt and a pcapng file, the first two which we dont know what to do with\
the pcapng contained several USB packets, which means we're extracting user inputs here\
some of the packets contains HID data:
### extracting
select the target USB packet, right click on HID Data and apply as column\
now copy and format so they can be thrown into https://github.com/TeamRocketIst/ctf-usb-keyboard-parser/\
(note: it will show a warning a byte is invalid. the repo somehow didnt include '?', so manually add it in list)
### decoding flag.txt
after extracting we're greeted with the encryption process of flag.txt:
```
nvim flag.txt
:%s/0/10101/g
:%s/1/10011/g
:%s/[01]/?=system("awk '[CAPSLOCK][CAPSLOCK]NR % 2 ==".(submatch(0) == "0" ? "0" : "1")."' synoonyms.txt ? shuf -n1")/g
```
which basically means
```py
replace 0 with 10101
replace 1 with 10011
for x in flag.txt:
  if x == "0":
    append a random even-lined word in synoonyms
  else:
    append a random odd-lined word in synoonyms
```
we can reverse the encryption easily:
```py
with open("synoonyms.txt", 'r') as wordlist_file:
    words = [line.strip() for line in wordlist_file]

with open("flag.txt", 'r') as flag_file:
    flag_lines = [line.strip() for line in flag_file]
    
dec = ""
for word in flag_lines:
    i = words.index(word)
    print(i+1)
    if (i +1) % 2 == 0:
        dec += "0"
    else:
        dec += "1"
print(dec)
```
then just cyberchef it because idk how to do it in python\
flag: **`apoorvctf{ne0v1m_1s_b3tt3r}`**

# Blend in Disguise
ill let my teammate thesis take over this one:

## Steps
 - The `chall.zip` contains two files: `hint.txt` and `chal.blend`. Opening the `chal.blend` in Blender we see a 25x25 grid of cubes, each with an animation spanning 4 frames.
 
 - Let's write (or have ChatGPT write) a simple python script in the `Scripting` tab of Blender to extract animation data. 

```py
import bpy

def get_animation_data():
    output_lines = []
    
    for obj in bpy.data.objects:
        if obj.animation_data and obj.animation_data.action:
            output_lines.append(f"Object: {obj.name}\n")
            
            for fcurve in obj.animation_data.action.fcurves:
                data_path = fcurve.data_path
                index = fcurve.array_index
                output_lines.append(f"  Property: {data_path}[{index}]\n")
                
                for keyframe in fcurve.keyframe_points:
                    frame = keyframe.co[0]
                    value = keyframe.co[1]
                    output_lines.append(f"    Frame {frame}: {value}\n")
            
            output_lines.append("\n")
    
    return output_lines

def save_to_file(filepath):
    lines = get_animation_data()
    with open(filepath, "w") as file:
        file.writelines(lines)
    print(f"Animation data saved to {filepath}")

# Change the file path as needed
save_to_file("/tmp/blender_animation_data.txt")
```

- In the saved file, we can see that only two properties are changing per keyframe `scale[2]` and `location[2]` which correspond to the z-value of the scale (size) and location properties. Additionally, we can see that the location is always half of the scale, this is because the location of a 3D object is always its center, as the height of the object is changing, so is its center. Hence, we can safely ignore the `location[2]` property and focus on `scale[2]`

- Now going back to the hint, let us try to figure out what it means. 

> Gather values, sum with care,
> At every key, a weight to bear.
> Tip the scales—one thousand’s gate,
> Decide the path, control the fate.
> 
> One side dark, the other light,
> Opposing forces, black and white.
> Balance shifts, the truth unveiled,
> A sight well known, a tale retold.

`Gather values, sum with care, At every key, a weight to bear`  seems to imply that we need to sum a certain value obtained from the key(frames). While we did choose to ignore the `location[2]` property, we can easily test it later since its just the half of `scale[2]`

`Tip the scales—one thousand’s gate, Decide the path, control the fate.` I'll come back to this later

`One side dark, the other light, Opposing forces, black and white` This seems to imply that some sort of correlation between positive-negative/black-white will be involved.

`A sight well known, a tale retold.` Seems to imply that the final output we are looking for might be an image.

- At this point, I decided to sum the scales for each of the cubes across all keyframes to see if anything interesting came out of it.
```py
import bpy

def get_scale_sums():
    output_lines = []
    
    for obj in bpy.data.objects:
        if obj.animation_data and obj.animation_data.action:
            total_scale_z = 0
            
            for fcurve in obj.animation_data.action.fcurves:
                if fcurve.data_path == "scale" and fcurve.array_index == 2:
                    total_scale_z = sum(keyframe.co[1] for keyframe in fcurve.keyframe_points)
            
            output_lines.append(f"{obj.name}: {total_scale_z}\n")
    
    return output_lines

def save_to_file(filepath):
    lines = get_scale_sums()
    with open(filepath, "w") as file:
        file.writelines(lines)
    print(f"Scale sum data saved to {filepath}")

# Change the file path as needed
save_to_file("/tmp/blender_scale_sums.txt")

```

- In the data, I noticed all the values were pretty close to 1000. At this point, the hint finally made sense: `Tip the scales—one thousand’s gate` "gate" means threshold, so 1000 was likely the threshold for deciding black and white. I decided the easiest way to render an image from this was to put it in excel sheets.

- Scanning the QR code, gives us the flag: **`apoorvctf{bl3nd3r_1s_fuN}`**