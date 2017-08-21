---
layout: post
title:  "Another 'Getting Started in Security' Post"
date:   2017-08-21 08:00:00 -0400

---

As stated in my ["about me"](/about) page, there have been more than a few conversations that involved someone asking me how I successfully "broke" into the information security field and, more importantly, how they could as well. Although this topic has been covered quite a bit, I felt it would be beneficial to offer my two cents to others looking to follow a similar path. However, I would **strongly** recommend you read the following posts before diving into my content:

* [So, you want to work in security?](https://medium.freecodecamp.org/so-you-want-to-work-in-security-bc6c10157d23){:target="_blank"} by [Parisa Tabriz](https://twitter.com/laparisa){:target="_blank"}
* [So you want to work in security (but are too lazy to read Parisa's excellent essay)](https://lcamtuf.blogspot.com/2016/08/so-you-want-to-work-in-security-but-are.html){:target="_blank"} by [Michal Zalewski](https://twitter.com/lcamtuf){:target="_blank"}
* [Answers on how to get started in Security](http://carnal0wnage.attackresearch.com/2015/05/answers-on-how-to-get-started-in.html){:target="_blank"} by [Chris Gates](https://twitter.com/carnal0wnage){:target="_blank"}
* [How to become a pentester](https://www.corelan.be/index.php/2015/10/13/how-to-become-a-pentester/){:target="_blank"} by [Peter Van Eeckhoutte](https://twitter.com/corelanc0d3r){:target="_blank"}

Foundation, Foundation, Foundation 
------

A significant portion of hacking is:

1. Understanding how your target operates under normal circumstances (in many cases, the implementation does not strictly abide by the intended design); and 
2. Either manipulating the target to deviate from normal behavior or abuse the lax implementation to achieve a malicious goal.  

Although certainly not a novel concept, the message is vital to becoming a successful security professional. This holds doubly true for the defensive side of the ball. Information security is a perpetual game of "cat and mouse". For defensive security specialists, staying on top of the latest and most effective offensive techniques plays a major role in securing things. Conversely, offensive security specialists need to constantly adapt and/or redesign their techniques to bypass said defenses.

Despite being seemingly generic advice, this resonates with me more and more each day. Without comprehensive and intimate knowledge of your target, it becomes exponentially more difficult to secure or compromise it. The next logical question is naturally, "What do I need to know?" I've provided several topics below that will help aspiring security professionals to hit the ground running. Note that this is not, by any means, a comprehensive list. 

* <b>Network Security</b>
	* TCP vs. UDP and common services using both
	* Common network protocols (e.g., ARP, DHCP, DNS)
	* Firewall configuration (ingress vs. egress policies) using utilities such as iptables and pf
	* Active Directory environment setup and management
	* Windows and Linux administration

* <b>Application Security</b>
	* HTTP/HTTPS
	* Authentication and authorization models
	* Session management
	* Basic web application development (e.g., HTML, JavaScript)
	* Database access/queries
	* Basic cryptography (public and private key cryptosystems, key exchange protocols, message integrity)

* <b>Reverse Engineering & Exploit Development</b>
	* Computer Architecture
	* Basic C programming
	* Usermode debugging (gdb, OllyDbg) 
	* Using popular disassemblers (IDA, Binary Ninja, Hopper)
	* Getting comfortable with assembly language (ARM, x86)
	* Common exploitation techniques (stack overflow, use-after-free, etc.)
	* Operating Systems

Education, Certifications & Prior Experience
------

My academic background stemmed from an undergraduate degree in computer engineering. Although this helped me gain exposure to many of the topics I had listed above, I decided to supplement this with a graduate degree in cybersecurity after spending a few years in the field. Let me be clear, although the route to my professional career took me through academic schooling, this is certainly **not** the only route. I know a slew of security professionals from varying walks of life - philosophers, physics majors, former art and theater students. Some of these bright minds decided not to pursue an official education beyond high school, and they're phenomenal at what they do. In my eyes, that's one (of many) particular aspect of this industry that makes it unique. 

It is for this exact reason that this portion of the journey is completely dependent on personal preference. If you're the type that thrives in a traditional, academic environment, there are degrees (both online and on-campus) offered by several universities that can fit your needs. Conversely, if you prefer self-study and personal projects, there are more than enough resources online to facilitate that process. Of course, a combination of both approaches is perfectly feasible and effective as well.

> <b>*Note:</b> If you decide to research potential colleges and universities for undergraduate or graduate security programs, be sure to carefully vet the curriculum. There are establishments that advertise information security or cybersecurity programs, but they may teach strictly from a management, compliance or theoretical perspective without including the technical, hands-on techniques necessary for practical execution.

A popular subcategory within this point of discussion is centered around certifications. Again, I pursued this route because my personal preference is to follow a curriculum, course materials and exercises to get started in a specific area, but my advice remains the same. Official certifications, although valuable, are not a prerequisite or necessity for every aspiring (or established) security professional. Having said that, [Offensive Security](https://www.offensive-security.com/){:target="_blank"} offers a series of excellent courses for those looking to specialize in network penetration testing, exploit development, web application security and/or wireless network security. Earlier this year, I had successfully passed the [PWK](https://www.offensive-security.com/information-security-training/penetration-testing-training-kali-linux/){:target="_blank"} exam and achieved my OSCP certification, and I can say with confidence that it was a very valuable, but equally trying experience. It's now a few months later, and I've already found myself enrolled in the [CTP](https://www.offensive-security.com/information-security-training/cracking-the-perimeter/){:target="_blank"} course and pursuing my OSCE certification.

The same individuals asking for my advice have consistently inquired about prior experience that may be necessary to get their foot in the door and obtain their first job in the field. The recurring theme rears its head once again - it is helpful along the way, but most definitely not required. Those same security professionals that I know (on one level or another) differ wildly in their professional experience prior to entering the infosec field. Some were system administrators or network engineers for nearly a decade before making the pivot to security. Others (myself included) do not have such experience under their belt, but have never been at a disadvantage. 

Landing that initial job in infosec is only limited by your willingness to succeed and dedication to feeding an insatiable hunger for more knowledge (a LinkedIn profile helps too). As clich&eacute; as this seems, its truth is sound. This shines through when interacting with peers, perhaps discussing each other's current personal projects, and sharing a moment where you both realize your eyes are bigger than your stomach. This is why I will always have a stack of books on my shelf or a bookmark folder filled with articles and GitHub repositories, and despite my best efforts, they will never be empty.

Dive Right In
------

Put your acquired knowledge to the test with practical examples, CTF (capture the flag) challenges, "crackmes", vulnerable virtual machines, etc. Once you become comfortable with the foundational knowledge necessary to move forward with these projects and exercises, it would be immensely beneficial to become equally comfortable reading and writing in at least two programming languages. I highly recommend these be C and Python. Understanding how to program in C and what occurs "under the hood" is imperative to understanding key concepts such as memory management, pointers, and string formatting and manipulation (many of which map directly to software exploitation techniques). As a scripting language, Python offers a vast set of modules, making it a very flexible option complete with a low barrier for entry. Again, these are not the only programming languages for consideration (others have chosen Java, Go, among others).

These practice labs, applications, websites and exercises can be found in a multitude of places, but here is a small sample set:

* [Hack This Site!](https://www.hackthissite.org/){:target="_blank"}
* [Infosec Rocks](https://sites.google.com/site/infosecrocks/){:target="_blank"}
* [Microcorruption](https://microcorruption.com/login){:target="_blank"}
* [Exploit Exercises](https://exploit-exercises.com/){:target="_blank"}
* [Metasploitable3](https://github.com/rapid7/metasploitable3){:target="_blank"}
* [CTF Time](https://ctftime.org/){:target="_blank"}

For the latest news, tools, techniques, white papers and the like, the [netsec subreddit](https://www.reddit.com/r/netsec/){:target="_blank"} is a phenomenal and frequently updated resource. Twitter is another bountiful option, but it may require some additional culling.

Resist the Temptation
------

As with any other career path or area of expertise, it is tempting to take shortcuts in order to expedite progress. Within infosec, these shortcuts typically take the form of open-source tools and customized virtual machines/Linux distributions. Although these tools are staples within the seasoned security professional's arsenal, their potential is limited by the knowledge of the one wielding the tool. For example, it is relatively straightforward to point nmap at a target subnet or single host, copy and paste a string of frequently used options, and analyze the output "as is". Without an intimate understanding of how the tool sends and analyzes TCP/UDP network traffic, the user may miss out on key pieces of information - services running on non-standard ports (e.g., SSH on TCP port 5555), open ports falling outside the scanned range, firewall evasion, etc. 

In short, the operator should fully understand how the "cogs and gears" of the tool turn, and why. Don't get lost in the sea of available security tools all at once. Taking the time to reinforce your knowledge of fundamental information security concepts and subject matter will pay back tenfold, as you'll be able to harness the full potential of such tools (and even empower yourself to create/share your own!).

Lean on (and Become Part of) the Community
------

I would not be where I am today without the aid of the infosec community. So many people have been beyond eager to share their knowledge, help others, and further the state of offensive and defensive security by challenging their peers. I implore those setting foot on the path to becoming a security professional to not only reap the benefits that the infosec community has to offer, but to pay it forward by contributing as well (after all, knowledge sharing is a two-way street). 

Whether the medium is social media, attending security conferences, or sitting in on webinars, immerse yourself in other's experience. In my eyes, this is an exceptional catalyst for security professionals at any stage in their career. **Do not feel intimidated or afraid to ask questions**. 

Although I can write on the topic for many, many more pages, this should suffice in, at the very least, pointing a few of you in the right direction. In the spirit of this post and the infosec community at large, please do not hesitate to contact me on [Twitter](https://twitter.com/0xdeadbeefjerky){:target="_blank"} if you have any questions or you're looking for additional advice. 

Happy \(hacking\|hunting\)!