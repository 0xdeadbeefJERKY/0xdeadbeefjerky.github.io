---
title:  "Windows Internals Course Review"
description: This post describes my experience in taking the Windows Internals course offered by Pavel Yosifovich and how it has boosted my capabilities as an offensive security researcher and red teamer.
date:   2019-01-01 22:30:00 -0400
categories: [Training, Windows Internals] 
tags: [windows, internals, training]
toc: true
---

## TL;DR
Quite frankly, this training is for anyone **but** those looking to skim material with a brief TL;DR section. Rather, it caters best to security professionals looking to roll up their sleeves and dive deep into the cogs and gears of the Windows operating system. If you fit this description, read on closely and carefully. 

> This training isn't tailored *only* for security professionals. Some of the attendees were system administrators, Windows developers, etc.
{: .prompt-tip }

## Credit Where Credit is Due
A thousand thanks to [Pavel Yosifovich](https://twitter.com/zodiacon){:target="_blank"} for authoring the content for this training and delivering it to myself and my fellow attendees during unsavory hours to accommodate our respective time zones.

## The Who
### Your Guide
Pavel Yosifovich literally rewrote and updated the book on Windows Internals (alongside [Alex Ionescu](https://twitter.com/aionescu){:target="_blank"}, credit to original authors [Mark Russinovich](https://twitter.com/markrussinovich){:target="_blank"} and David A. Solomon as well) to cover material specific to the releases of Windows 8, Windows 8.1 and Windows 10. You couldn't be in better hands but if you're still skeptical, check out his [blog](http://blogs.microsoft.co.il/pavely/){:target="_blank"} and [GitHub repos](https://github.com/zodiacon?tab=repositories){:target="_blank"}.

### Who Should Take This Training?
Offensive and defensive information security professionals interested in Windows security will benefit greatly from this course. Crafting a detailed and in-depth understanding of both Microsoft's security model as well as the architectural designs and operations of the Windows operating system empower security folks with the ability to effectively attack and defend Windows endpoints. If you're currently in or aspire to be in one (or more) of the following roles, put this training at the top of your list:

* Red teaming
* Penetration testing
* Exploit development and vulnerability research
* Reverse engineering
* Anything involving monitoring, detection and/or response capabilities specific to Windows

## The What
Pavel's [Windows Internals training](https://scorpiosoftware.net/2018/08/17/public-remote-windows-internals-training/){:target="_blank"} traverses the content within the [Windows Internals Part 1 (7th edition) book](https://www.amazon.com/Windows-Internals-Part-architecture-management/dp/0735684189){:target="_blank"} in great detail across five days, covering the following eight topics:

1. System Architecture
2. Processes and Jobs
3. Threads
4. Kernel Mechanisms
5. Memory Management
6. Management Mechanisms
7. I/O System
8. Security

Pavel supplements and enforces a vast majority of this content with open-sourced Windows tooling (most of which he authored himself), various coding projects, and sessions spent in the wonderful world of WinDbg (this is **not** sarcasm, WinDbg is powerful and awesome). This hands-on time gives trainees the experience needed to pursue efforts above and beyond the scope of the given training material, which is vital for offensive security researchers looking to poke holes in the Windows OS, blue teamers validating and buffing their security controls, and even AV/AM/EDR authors.

## The Where
This particular instance of Pavel's training was delivered remotely, but keep track of his Twitter account and website for upcoming training locations.

## The Why
Because my current position and strongest area of expertise involves red teaming, I'll cover this section from a red teamer's point of view (but this can easily be "ported over" to other offensive and defensive perspectives as well).

### Pulling Back the Curtain
Being able to pull back the curtain on the Windows operating system is exactly what this course aims to achieve. As a red teamer, my primary objective was to understand the inner workings of every component of the Windows OS so that I can use that knowledge to create bypasses, evasion and execution techniques, etc. I'll use a portion of the section covering processes as an example. 

Many offensive security folks understand the basic concept of a process, such as parent/child processes, process IDs, starting and killing processes. This course covers, in detail, not only every detailed step of process creation, but the entirety of the process lifecycle and the prerequisites for each phase/transition. This content is further enforced by having participants walk through a lab to create and manage Windows processes via the Windows API (C/C++, .NET). 

### The Times, They Are A-Changin'
As a red teamer, I need to periodically reevaluate my tooling to ensure I have the ability to gain initial execution, escalate privileges, achieve persistence, evade detection, etc. This is especially true considering the current shift to environments running mostly (or entirely) Windows 10/2016 endpoints. Although some older attack paths and vulnerabilities still exist, the days of unquoted service paths and SMB null sessions are quickly fading away.

Currently, (some) attackers face enforcement of signed kernel drivers, Virtualization-Based Security (VBS), Protected Processes (and Protected Processes Light), among many other well-positioned hurdles. Gaining an intimate understanding of not only the operating system components themselves and how they interact with each other, but also how the latest and greatest protections fit into the picture is vital in order to research and test novel attack techniques and unearthing new attack surfaces.

As an example, attackers have been leaning on the capabilities of Mimikatz and similar software to extract and manipulate Windows credentials. The latest release of Windows 10 forces such software to bypass the latest protections by as of this writing) either installing a kernel driver or capturing credentials as they are entered during logon or similar events. These two specific scenarios might not be feasible or OPSEC-safe for most red teamers. The knowledge obtained during this course put offensive security researchers in an excellent position to uncover novel credential compromise and malicious use techniques.

## The Verdict
Modern exploitation on Windows (both in userland and kernel space), especially with the release of Windows 10/Server 2016, is continually requiring more in-depth and intimate understanding of the Windows operating system as well as its security mechanisms. This course begins with the foundational knowledge and proceeds to take a deep dive into every outlined component of the Windows operating system, not only those that strictly pertain to security. Having gone through this course, I feel much better prepared for both spearheading and understanding Windows-related security research efforts. As a result, I personally believe this has made me a much more valuable red teamer. 

As always, feel free to reach out via [Twitter](https://twitter.com/0xdeadbeefJERKY){:target="_blank"} with any questions/comments.

Happy (hacking\|hunting)!
