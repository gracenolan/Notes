# Security Engineering at Google: My Interview Study Notes
## By [nolang](https://twitter.com/__nolang)

I am a security engineer at Google and these are the notes from when I was studying for the interviews. This is my first job in security and a lot of people have asked me how I studied. My notes consist mostly of a list of terms and technologies to learn, plus little tidbits that helped me remember certain details. I've included interview tips and study strategies which are just as important as knowing what topics to study.

I occasionally update the notes to include more topics. There are many, many topics and terms in the list. Think carefully about the role you are applying for and target your study towards that. No one expects you to be an expert in everything.

**If you are less confident at coding:** 
Spend more time writing small scripts and studying features of your preferred language. Coding is essential (even if you don't like it or you don't use it much in your current role). I have a section on coding in this list.

**If you are less confident at security topics:** 
I recommend doing a lot of reading and whenever you come across a term you are unfamiliar with or couldn't easily explain, then add it to the list. 

### 5 Years Later [Update]
I've been at Google for few years now and I have been delighted to learn of how many people have used these notes! Not just to get offers from Google but to get their first jobs in this industry, or to change focus area. I love hearing these stories! 

Since joining I have also learned what keeps most people from getting through the Google Security Egnineering interview process. **The number one reason why a candidate misses out on an offer is because they struggle with the coding questions.**

I have two things to say on this:
1. **Improving coding skills takes a lot of practice.** Be sure to allow yourself enough time for it, including allowing time to be frustrated, to procrastinate, to iterate on your ideas, and to get help from others. Look for ways to make it fun or motivating - there are tedius repetitive tasks everywhere just waiting to be automated. 
2. **It is completely normal and acceptable to interview again** (many times, in fact!). Hiring managers love to see how someone has grown their skills over time.

If you are someone who didn't get an offer because you weren't confident in some areas, but you still believe that it would be a good role/company for you, take some time to build confidence in those areas and try again. 

Finally, pull requests are welcome! Thank you to those who have made contributions and are helping to keep the list up to date.

### Contents
- [1.0 General Tips](interview-study-notes-for-security-engineering.md#10-general-tips)
	- [1.1 Learning Tips](interview-study-notes-for-security-engineering.md#11-learning-tips)
	- [1.2 Interviewing Tips](interview-study-notes-for-security-engineering.md#12-interviewing-tips)
- [2.0 Networking](interview-study-notes-for-security-engineering.md#20-networking)
	- [2.1 Infrastructure (Prod / Cloud) Virtualisation](interview-study-notes-for-security-engineering.md#21-infrastructure-prod--cloud-virtualisation)
- [3.0 Web Application](interview-study-notes-for-security-engineering.md#30-web-application)
- [4.0 OS Implementation and Systems](interview-study-notes-for-security-engineering.md#40-os-implementation-and-systems)
- [5.0 Coding & Algorithms](interview-study-notes-for-security-engineering.md#50-coding--algorithms)
	- [5.1 Security Themed Coding Challenges](interview-study-notes-for-security-engineering.md#51-security-themed-coding-challenges)
- [6.0 Offensive Security](interview-study-notes-for-security-engineering.md#60-offensive-security)
	- [6.1 Attack Structure](interview-study-notes-for-security-engineering.md#61-attack-structure)
	- [6.2 Exploits](interview-study-notes-for-security-engineering.md#62-exploits)
	- [6.3 Malware & Reversing](interview-study-notes-for-security-engineering.md#63-malware--reversing)
	- [6.4 Digital Forensics](interview-study-notes-for-security-engineering.md#64-digital-forensics)
- [7.0 Defensive Security](interview-study-notes-for-security-engineering.md#70-defensive-security)
	- [7.1 Threat Modeling](interview-study-notes-for-security-engineering.md#71-threat-modeling)
	- [7.2 Detection](interview-study-notes-for-security-engineering.md#72-detection)
	- [7.3 Cryptography, Authentication, Identity](interview-study-notes-for-security-engineering.md#73-cryptography-authentication-identity)
	- [7.4 Incident Management](interview-study-notes-for-security-engineering.md#74-incident-management)
	- [7.5 Mitigations](interview-study-notes-for-security-engineering.md#75-mitigations)
