# Problem

we want to correct data from testssl on our list of domain, 60,000 domian. Each testssl have process time around 60-120 sec. Assume for best case 60 * 60,000 = 3,600,000 sec which is around 42 days. Bash script will not cut it  

# What can we do

## Multithread

### Python

First i think of Python but python use **Global Interpreter Lock (GIL)** and testssl is outside process. This will be I/O bound and add overhead with GIL combine with MY POOL LOCAL MACHINE can’t not handle python memory usage since we work 60,000 domain and that a lot of memory  

A basic Python "Hello World" or idle script typically uses **15MB to 30MB** so 60,000 will take around **1.8 Terabytes** of RAM if we don’t do it properly. This number come from memory of thread need in python.

### C++

That why it fall to C++. atomic multithread can run multiple thread together and better memory control.

I think about using this with SQLite since we probably run this for a long time. That why i need fallback if error to happened inside program. I know i can’t cover all the edge case. That why i will let SQLite handle it. 

# About testssl

we can write our agent meta in testssl so we don’t need to use curl anymore

```bash
COMPANY="Your Company"
EMAIL="you@company.com"
PURPOSE="TLS security compliance assessment"
UA="SecurityAudit/1.0 (Org: $COMPANY; Contact: $EMAIL; Purpose: $PURPOSE)"

./testssl.sh --useragent "$UA"
```