---
layout: post
title:  "The Current State of DDE"
description: The Dynamic Data Exchange (DDE) protocol exposes functionality that allows data to be transmitted between applications/processes on Windows platforms. About two years ago, researchers discovered that this protocol could be abused in order to achieve arbitrary command and code execution, more specifically within Microsoft Office applications (e.g., Excel). Within the past few months, Microsoft issued several updates to combat these attacks. This post will address the current state of the DDE attack vector within Microsoft Office applications, taking the recent patches and security advisories from Microsoft into account.
date:   2018-01-29 07:38:00 -0400
crosspost_to_medium: false
---

<title>
   {%if page.title %}
       {{ page.title }}
   {% else %}
       {{ site.title }}
   {% endif %}
</title>

Update #1 (1/29/2018)
------

Hours after the release of this post, [Matt Nelson](https://twitter.com/enigma0x3){:target="_blank"} unleashed a [new technique](https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee){:target="_blank"} to bypass the latest mitigation options made available by Microsoft. As a result, attackers can embed an Excel spreadsheet within OneNote in order to completely bypass the corresponding registry key intended to block DDE functionality. Furthermore, OneNote documents downloaded from external sources (e.g., the public Internet) are (still) not sandboxed by Protected View. I’ve added another item to the roadmap for my Office DDE payload generation tool, as I intend to automate this technique as well.

TL;DR
------

Microsoft pushed an update that disables DDE functionality within Word by default. However, this default setting can be nullified by setting a single registry key value. All other Office applications remain (relatively) vulnerable to DDE abuse attacks, but protection can be opted into by setting specific registry keys for each product.

DDE Attacks: Origins Story
------

The [Dynamic Data Exchange (DDE) protocol](https://msdn.microsoft.com/en-us/library/windows/desktop/ms648774(v=vs.85).aspx){:target="_blank"} exposes functionality that allows data to be transmitted and shared between applications/processes on Windows platforms.  Back in 2014, [James Kettle](https://twitter.com/albinowax){:target="_blank"} and [Rohan Durve](https://twitter.com/decode141){:target="_blank"} released [a blog post](https://www.contextis.com/blog/comma-separated-vulnerabilities){:target="_blank"} describing the formula injection technique affecting Microsoft Excel, which can be abused in order to achieve arbitrary command execution by way of the DDE protocol. About two years later, [Jerome Smith](https://twitter.com/exploresecurity){:target="_blank"} delivered a [presentation at CamSec](https://www.slideshare.net/exploresecurity/camsec-sept-2016-tricks-to-improve-web-app-excel-export-attacks){:target="_blank"} detailing a technique that abused DDE in Excel to achieve arbitrary command and code execution. This served as a catalyst for subsequent offensive research led by many, including [Saif Sherei](https://twitter.com/Saif_Sherei){:target="_blank"}, [Etienne Stalmans](https://twitter.com/_staaldraad){:target="_blank"}, [Kevin Beaumont](https://twitter.com/gossithedog){:target="_blank"}, [Ryan Hanson](https://twitter.com/ryhanson){:target="_blank"}, and [Mike Czumak](https://twitter.com/securitysift){:target="_blank"}. As a result, similar techniques abusing the DDE protocol were crafted for other applications within the Microsoft Office product line, specifically, Word and Outlook. Shortly after this research was publicized, malware samples and phishing documents surfaced "in the wild" that leveraged these techniques. The following posts cover these DDE attacks:

- [https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/](https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/){:target="_blank"}
- [https://sensepost.com/blog/2017/macro-less-code-exec-in-msword](https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/){:target="_blank"}
- [http://staaldraad.github.io/2017/10/23/msword-field-codes/](http://staaldraad.github.io/2017/10/23/msword-field-codes/){:target="_blank"}
- [https://www.securitysift.com/abusing-microsoft-office-dde/](https://www.securitysift.com/abusing-microsoft-office-dde/){:target="_blank"}
- [https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/](https://pentestlab.blog/2018/01/16/microsoft-office-dde-attacks/){:target="_blank"}

In the midst of all this, several tools were created to leverage this offensive technique and released for public use. [Panagiotis Gkatziroulis](https://twitter.com/netbiosX){:target="_blank"} covered the usage and functionality of such tools in their [post on Medium](https://medium.com/red-team/dde-payloads-16629f4a2fcd){:target="_blank"}, which includes my DDE payload generation tool [available on GitHub](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads){:target="_blank"}.



Microsoft Fights Back
------

Starting in November of 2017, Microsoft began issuing several Windows updates and advisories to combat these attacks. [Microsoft Security Advisory 4053440](https://technet.microsoft.com/en-us/library/security/4053440.aspx){:target="_blank"} provides explicit detail regarding the changes that Microsoft made to DDE functionality and behavior in the context of Office applications. Originally, Microsoft provided some "defense-in-depth" options for Windows users, allowing for more granular control over allowed DDE functionality within Office applications. Microsoft then issued an update that changed default DDE behavior.



The Rub
------

As of this writing, these updates simply disabled DDE functionality within all versions of Microsoft Word by default. This leaves the DDE protocol enabled by default for the remaining Office applications that have been identified as vulnerable, notably Excel and Outlook. Additionally, Microsoft offered users the ability to override this default setting in Word by way of the Windows registry in order to support legacy applications that rely on the DDE protocol. Although this update puts a damper on Word DDE attacks "out of the box", both attackers and administrators can utilize the special registry key noted below to side-step the patch:

```
\HKEY_CURRENT_USER\Software\Microsoft\Office<version>\Word\Security AllowDDE(DWORD)
```

[Microsoft Security Advisory ADV170021](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV170021){:target="_blank"} outlines the three values to which this registry key can be set. Needless to say, potential attackers could either forcefully set the value to "2" or hope the environment's administrators have already done so.

- 0: To disable DDE. This is the default setting after you install the update.
- 1: To allow DDE requests to an already running program, but prevent DDE requests that require another executable program to be launched.
- 2: To fully allow DDE requests.

The Word DDE attack has traditionally been leveraged during targeted phishing campaigns, so the likelihood of an attacker creating or otherwise modifying this registry key after having already gained a foothold on the target machine is relatively low. However, as previously mentioned, there is the possibility that an administrator creates the registry key and sets its value to "2" in order to support legacy applications or services.



The Silver Lining
------

Although this appears problematic, these advisories present a way to apply granular control over DDE functionality across all affected Office applications. These options can be enabled and disabled by way of specific registry keys, also detailed in [Microsoft Security Advisory ADV170021](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV170021#ID0EMGAC){:target="_blank"} and [this gist](https://gist.github.com/wdormann/732bb88d9b5dd5a66c9f1e1498f31a1b){:target="_blank"} posted by [Will Dormann](https://twitter.com/wdormann){:target="_blank"}.



The Bottom Line and Office DDE Payload Generator Update
------

After all is said and done, Microsoft Word is still vulnerable to DDE attacks *if* the appropriate registry key is set. All other Office applications are vulnerable by default, as the latest Microsoft update only addressed the default behavior of DDE in Word. Please note that your mileage may vary with Outlook DDE attacks because some email providers automatically convert messages to HTML formatting before delivery to the recipient. This will strip any DDE elements out of the original rich text formatted (RTF) message.

As a byproduct of this post, I have updated my Office DDE payload generation tool to include simple Excel DDE payload generation. The tool roadmap includes adding another script to generate Outlook DDE payloads and research potential obfuscation and evasion techniques for both Excel and Outlook DDE payloads.

As always, feel free to reach out via [Twitter](https://twitter.com/0xdeadbeefJERKY){:target="_blank"} with any questions/comments.

Happy (hacking\|hunting)!

{% include share-page.html %}