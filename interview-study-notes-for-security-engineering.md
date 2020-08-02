# Security Engineering at Google: My Interview Study Notes
## By [nolang](https://twitter.com/__nolang)

I am a security engineer at Google and these are the notes from when I was studying for the interviews. This is my first job in security and a lot of people have asked me how I studied. My notes consist mostly of a list of terms and technologies to learn, plus little tidbits that helped me remember certain details. At the end are interview tips I made for myself and that I find myself saying to others looking to interview.

**If you are less confident at coding:** 
Spend more time writing small scrips and studying features of your preferred language. Coding is essential (even if you don't like it or you don't use it much in your current role). I have a section on coding in this list.

**If you are less confident at security topics:** 
I recommend doing a lot of reading and whenever you come across a term you are unfamiliar with or couldn't easily explain, then add it to the list. 

### Contents
- [Networking](#networking)
- [Web application](#web-application)
- [Infrastructure (Prod / Cloud) Virtualisation](#infrastructure-prod--cloud-virtualisation)
- [OS implementation and systems](#os-implementation-and-systems)
- [Mitigations](#mitigations)
- [Cryptography, authentication, identity](#cryptography-authentication-identity)
- [Malware & Reversing](#malware--reversing)
- [Exploits](#exploits)
- [Detection](#detection)
- [Digital Forensics](#digital-forensics)
- [Incident Management](#incident-management)
- [Coding & algorithms](#coding--algorithms)
- [Security themed coding challenges](#security-themed-coding-challenges)
- [Learning tips](#learning-tips)
- [Interviewing tips](#interviewing-tips)


# Networking 

- OSI Model
	- Application; layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
	- Transport; layer 4 (TCP/UDP).
	- Network; layer 3 (Routing).
	- Datalink; layer 2 (Error checking and frame synchronisation).
	- Physical; layer 1 (bits over fibre).
	
-	Firewalls
	- Rules to prevent incoming and outgoing connections.
	
-	NAT 
	- Useful to understand IPv4 vs IPv6.

- DNS
	- (53)
	- Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection. Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. DNS sinkholes.
	- In a reverse DNS lookup, PTR might contain- 2.152.80.208.in-addr.arpa, which will map to  208.80.152.2. DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.

- DNS exfiltration 
	- Sending data as subdomains. 
	- 26856485f6476a567567c6576e678.badguy.com
	- Doesn’t show up in http logs. 

- DNS configs
	- Start of Authority (SOA).
	- IP addresses (A and AAAA).
	- SMTP mail exchangers (MX).
	- Name servers (NS).
	- Pointers for reverse DNS lookups (PTR).
	- Domain name aliases (CNAME).
 
- ARP
	- Pair MAC address with IP Address for IP connections. 

- DHCP
	- UDP (67, 68)
	- Dynamic address allocation (allocated by router). 

- Multiplex 
	- timeshare, statistical share, just useful to know it exists.

- Traceroute 
	- Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
	- Initial hop-limit is 128 for windows and 64 for *nix. Destination returns ICMP Echo Reply. 

- Nmap 
	- Network scanning tool.

- Intercepts (MiTM) 
	- Understand PKI (public key infrastructure in relation to this).

- VPN 
	- Hide traffic from ISP but expose traffic to VPN provider.

- Tor 
	- Traffic is obvious on a network. 
	- How do organised crime investigators find people on tor networks. 

- Proxy  
	- Why 7 proxies won’t help you. 

- BGP
	- Border Gateway Protocol.
	- Holds the internet together.

- Network traffic tools
	- Wireshark
	- Tcpdump
	- Burp suite

- HTTP/S 
	- (80, 443)

- SSL/TLS
	- (443) 
	- Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. [A good primer on all these concepts and algorithms](https://english.ncsc.nl/publications/publications/2019/juni/01/it-security-guidelines-for-transport-layer-security-tls) is made available by the Dutch cybersecurity center.
	- (Various attacks against older versions of SSL/TLS (with catchy names)](https://en.wikipedia.org/wiki/Transport_Layer_Security#Attacks_against_TLS/SSL).

- TCP/UDP
	- Web traffic, chat, voip, traceroute.
	- TCP will throttle back if packets are lost but UDP doesn't. 
	- Streaming can slow network TCP connections sharing the same network.

- ICMP 
	- Ping and traceroute.

- Mail
	- SMTP (25, 587, 465)
	- IMAP (143, 993)
	- POP3 (110, 995)

- SSH 
	- (22)
	- Handshake uses asymmetric encryption to exchange symmetric key.

- Telnet
	- (23, 992)
	- Allows remote communication with hosts.

- ARP  
	- Who is 0.0.0.0? Tell 0.0.0.1.
	- Linking IP address to MAC, Looks at cache first.

- DHCP 
	- (67, 68) (546, 547)
	- Dynamic (leases IP address, not persistent).
	- Automatic (leases IP address and remembers MAC and IP pairing in a table).
	- Manual (static IP set by administrator).

- IRC 
	- Understand use by hackers (botnets).

- FTP/SFTP 
	- (21, 22)

- RPC 
	- Predefined set of tasks that remote clients can execute.
	- Used inside orgs. 

- Service ports
	-  0 - 1023- reserved for common services - sudo required. 
	- 1024 - 49151- registered ports used for IANA-registered services. 
	- 49152 - 65535- dynamic ports that can be used for anything. 

- HTTP Header
	- | Verb | Path | HTTP version |
	- Domain
	- Accept
	- Accept-language
	- Accept-charset
	- Accept-encoding(compression type)
	- Connection- close or keep-alive
	- Referrer
	- Return address
	- Expected Size?

- HTTP Response Header
	- HTTP version
	- Code- 200 OK, 403 forbidden, 404 not found, 500 server, 503 server unavailable, 301 Redirect notice 
	- Type of data in response 
	- Type of encoding
	- Language 
	- Charset

- UDP Header
	- Source port
	- Destination port
	- Length
	- Checksum

- Broadcast domains and collision domains. 
- Root stores
- CAM table overflow

# Web application 

- Same origin policy
	- Only accept requests from the same origin domain. 
 
- CORS 
	- Cross-Origin Resource Sharing. Can specify allowed origins in HTTP headers. Sends a preflight request with options set asking if the server approves, and if the server approves, then the actual request is sent (eg. should client send auth cookies).

- HSTS 
	- Policies, eg what websites use HTTPS.

- Cert transparency 
	- Can verify certificates against public logs 
	
- HTTP Public Key Pinning
	- (HPKP)
	- Deprecated by Google Chrome

- Cookies 
	- httponly - cannot be accessed by javascript.

- CSRF
	- Cross-Site Request Forgery.
	- Cookies.

- XSS
	- Reflected XSS.
	- Persistent XSS.
	- DOM based /client-side XSS.
	- `<img scr=””>` will often load content from other websites, making a cross-origin HTTP request. 

- SQLi 
	- (Wo)man in the browser (flash / java applets) (malware).
	- Validation / sanitisation of webforms.

- POST 
	- Form data. 

- GET 
	- Queries. 
	- Visible from URL.

- Directory traversal 
	- Find directories on the server you’re not meant to be able to see.
	- There are tools that do this.

- APIs 
	- Think about what information they return. 
	- And what can be sent.

- Beefhook
	- Get info about Chrome extensions.

- User agents
	- Is this a legitimate browser? Or a botnet?

- Browser extension take-overs
	- Miners, cred stealers, adware.

- Local file inclusion
- Remote file inclusion (not as common these days)

- SSRF 
	- Server Side Request Forgery.

- Web vuln scanners 
- SQLmap
- Malicious redirects


# Infrastructure (Prod / Cloud) Virtualisation 

- Hypervisors
- Hyperjacking
- Containers
- Escaping and privilege escalation techniques
- Site isolation
- Network connections from VMs / containers 
- Side-channel attacks 
- Beyondcorp 
	- Trusting the host but not the network.

# OS implementation and systems

- Privilege escalation techniques, and prevention
- Buffer Overflows 
- Directory traversal (prevention)
- Remote Code Execution / getting shells

- Local databases
	- Some messaging apps use sqlite for storing messages.
	- Useful for digital forensics, especially on phones.

- Windows
	- Windows registry and group policy. 
	- Windows SMB. 
	- Samba (with SMB).
	- Buffer Overflows. 
	- ROP. 

- *nix 
	- SELinux.
	- Kernel, userspace, permissions.
	- MAC vs DAC.
	- /proc
	- /tmp - code can be saved here and executed.
	- /shadow 
	- LDAP - Lightweight Directory Browsing Protocol. Lets users have one password for many services. This is similar to Active Directory in windows.

- MacOS
	- Gotofail error (SSL).
	- MacSweeper.
	- Research Mac vulnerabilities.

## Mitigations 
- Patching 
- Data Execution Prevention

- Address space layout randomisation
	- To make it harder for buffer overruns to execute privileged instructions at known addresses in memory.

- Principle of least privilege
	- Eg running Internet Explorer with the Administrator SID disabled in the process token. Reduces the ability of buffer overrun exploits to run as elevated user.

- Code signing
	- Requiring kernel mode code to be digitally signed.

- Compiler security features
	- Use of compilers that trap buffer overruns.

- Encryption
	- Of software and/or firmware components.

- Mandatory Access Controls
	- (MACs)
	- Operating systems with Mandatory Access Controls - eg. SELinux.

- "Insecure by exception"
	- When to allow people to do certain things for their job, and how to improve everything else. Don't try to "fix" security, just improve it by 99%.

- Do not blame the user
	- Security is about protecting people, we should build technology that people can trust, not constantly blame users. 


# Cryptography, authentication, identity 

- Encryption vs Encoding vs Hashing vs Obfuscation vs Signing
	- Be able to explain the differences between these things. 
	- [Various attack models (e.g. chosen-plaintext attack)](https://en.wikipedia.org/wiki/Attack_model).

- Encryption standards + implementations
	- [RSA (asymmetrical)](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).
	- [AES (symmetrical)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard).
	- [ECC (namely ed25519) (asymmetric)](https://en.wikipedia.org/wiki/EdDSA).
	- [Chacha/Salsa (symmetric)](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant).

- Asymmetric vs symmetric
	- Asymmetric is slow, but good for establishing a trusted connection.
	- Symmetric has a shared key and is faster. Protocols often use asymmetric to transfer symmetric key.
	- Perfect forward secrecy - eg Signal uses this.

- Cyphers
	- [Block vs stream ciphers](https://en.wikipedia.org/wiki/Cipher).
	- [Block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation).
	- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).

- Trusted Platform Module 
	- (TPM)
	- Trusted storage for certs and auth data locally on device/host.

- Integrity and authenticity primitives
	- [Hashing functions, e.g. MD5, Sha-1, BLAKE](https://en.wikipedia.org/wiki/Cryptographic_hash_function). Used for identifiers, very useful for fingerprinting malware samples.
	- [Message Authentication Codes (MACs)](https://en.wikipedia.org/wiki/Message_authentication_code).
	- [Keyed-hash MAC (HMAC)](https://en.wikipedia.org/wiki/HMAC).

- Entropy
	- PRNG (pseudo random number generators).
	- Entropy buffer draining.
	- Methods of filling entropy buffer.

- Certificates 
	- What info do certs contain, how are they signed? 
	- Look at DigiNotar.

- O-auth
	- Bearer tokens, this can be stolen and used, just like cookies.

- Auth Cookies
	- Client side.

- Sessions 
	- Server side.

- Auth systems 
	- SAMLv2o.
	- OpenID.

- Biometrics
	- Can't rotate unlike passwords.

- Password management
	- Rotating passwords (and why this is bad). 
	- Different password lockers. 

- U2F / FIDO
	- Eg. Yubikeys.
	- Helps prevent successful phishing of credentials.

- Compare and contrast multi-factor auth methods


# Malware & Reversing

- Interesting malware
	- Conficker. 
	- Morris worm.
	- Zeus malware.
	- Stuxnet.
	- Wannacry.
	- CookieMiner.

- Malware features
	- Various methods of getting remote code execution. 
	- Domain-flux.
	- Fast-Flux.
	- Covert C2 channels.
	- Evasion techniques (e.g. anti-sandbox).
	- Process hollowing. 
	- Mutexes.
	- Multi-vector and polymorphic attacks.
	- RAT (remote access trojan) features.

- Decompiling/ reversing 
	- Obfuscation of code, unique strings (you can use for identifying code).
	- IdaPro, Ghidra.

- Static / dynamic analysis
	- Describe the differences.
	- Virus total. 
	- Reverse.it. 
	- Hybrid Analysis.

# Exploits

- Three ways to attack - Social, Physical, Network 
	- **Social**
		- Ask the person for access, phishing. 
		- Cognitive biases - look at how these are exploited.
		- Spear phishing.
		- Water holing.
		- Baiting (dropping CDs or USB drivers and hoping people use them).
		- Tailgating.
	- **Physical** 
		- Get hard drive access, will it be encrypted? 
		- Boot from linux. 
		- Brute force password.
		- Keyloggers.
		- Frequency jamming (bluetooth/wifi).
		- Covert listening devices.
		- Hidden cameras.
		- Disk encryption. 
		- Trusted Platform Module.
		- Spying via unintentional radio or electrical signals, sounds, and vibrations (TEMPEST - NSA).
	- **Network** 
		- Nmap.
		- Find CVEs for any services running.
		- Interception attacks.
		- Getting unsecured info over the network.

- Exploit Kits and drive-by download attacks

- Remote Control
	- Remote code execution and privilege.
	- Bind shell (opens port and waits for attacker).
	- Reverse shell (connects to port on attackers C2 server).

- Spoofing
	- Email spoofing.
	- IP address spoofing.
	- MAC spoofing.
	- Biometric spoofing.
	- ARP spoofing.

- Tools
	- Metasploit.
	- ExploitDB.
	- Shodan - Google but for devices/servers connected to the internet.
	- Google the version number of anything to look for exploits.
	- Hak5 tools.

- Look at mitre attack matrix
	- https://attack.mitre.org/

# Detection

- IDS
	- Intrusion Detection System (signature based (eg. snort) or behaviour based).
	- Snort/Suricata rule writing
	- Host-based Intrusion Detection System (eg. OSSEC)

- SIEM
	- System Information and Event Management.

- IOC 
	- Indicator of compromise (often shared amongst orgs/groups).

- Things that create signals
	- Honeypots, snort.

- Things that triage signals
	- SIEM, eg splunk.

- Things that will alert a human 
	- Automatic triage of collated logs, machine learning.
	- Notifications and analyst fatigue.
	- Systems that make it easy to decide if alert is actual hacks or not.

- Signatures
	- Host-based signatures
		- Eg changes to the registry, files created or modified.
		- Strings in found in malware samples appearing in binaries installed on hosts (/Antivirus).
	- Network signatures
		- Eg checking DNS records for attempts to contact C2 (command and control) servers. 

- Anomaly / Behaviour based detection 
	- IDS learns model of “normal” behaviour, then can detect things that deviate too far from normal - eg unusual urls being accessed, user specific- login times / usual work hours, normal files accessed.  
	- Can also look for things that a hacker might specifically do (eg, HISTFILE commands, accessing /proc).
	- If someone is inside the network- If action could be suspicious, increase log verbosity for that user.

- Firewall rules
	- Brute force (trying to log in with a lot of failures).
	- Detecting port scanning (could look for TCP SYN packets with no following SYN ACK/ half connections).
	- Antivirus software notifications.
	- Large amounts of upload traffic.

- Honey pots
	- Canary tokens.
	- Dummy internal service / web server, can check traffic, see what attacker tries.

- Things to know about attackers
	- Slow attacks are harder to detect.
	- Attacker can spoof packets that look like other types of attacks, deliberately create a lot of noise.
	- Attacker can spoof IP address sending packets, but can check TTL of packets and TTL of reverse lookup to find spoofed addresses.
	- Correlating IPs with physical location (is difficult and inaccurate often).

- Logs to look at
	- DNS queries to suspicious domains.
	- HTTP headers could contain wonky information.
	- Metadata of files (eg. author of file) (more forensics?).
	- Traffic volume.
	- Traffic patterns.
	- Execution logs.

- Detection related tools
	- Splunk.
	- Arcsight.
	- Qradar.
	- Darktrace.
	- Tcpdump.
	- Wireshark.

- A curated list of [awesome threat detection](https://github.com/0x4D31/awesome-threat-detection) resources

# Digital Forensics

 - Evidence volatility (network vs memory vs disk)

 - Network forensics
   - DNS logs / passive DNS
   - Netflow
   - Sampling rate

 - Disk forensics
   - Disk imaging
   - Filesystems (NTFS / ext2/3/4 / AFPS)
   - Logs (Windows event logs, Unix system logs, application logs)
   - Data recovery (carving)
   - Tools
     - plaso / log2timeline
     - FTK imager
     - encase

 - Memory forensics
   - Memory acquisition (footprint, smear, hiberfiles)
   - Virtual vs physical memory
   - Life of an executable
   - Memory structures
   - Kernel space vs user space
   - Tools
     - Volatility
     - Google Rapid Response (GRR) / Rekall
     - WinDbg

  - Mobile forensics
    - Jailbreaking devices, implications
    - Differences between mobile and computer forensics
    - Android vs. iPhone

  - Anti forensics
    - How does malware try to hide?
    - Timestomping

  - Chain of custody

# Incident Management

- Privacy incidents vs information security incidents
- Know when to talk to legal, users, managers, directors.
- Run a scenario from A to Z, how would you ...

- Good practices for running incidents 
	- How to delegate.
	- Who does what role.
	- How is communication managed + methods of communication.
	- When to stop an attack.
	- Understand risk of alerting attacker.
	- Ways an attacker may clean up / hide their attack.
	- When / how to inform upper management (manage expectations).
	- Metrics to assign Priorities (e.g. what needs to happen until you increase the prio for a case)
    - Use playbooks if available

- Important things to know and understand
	- Type of alerts, how these are triggered.
	- Finding the root cause.
	- Understand stages of an attack (e.g. cyber-killchain)
	- Symptom vs Cause.
	- First principles vs in depth systems knowledge (why both are good).
	- Building timeline of events.
	- Understand why you should assume good intent, and how to work with people rather than against them.
    - Prevent future incidents with the same root cause

  - Response models
    - SANS' PICERL (Preparation, Identification, Containement, Eradication, Recovery, Lessons learned)
    - Google's IMAG (Incident Management At Google)

# Coding & algorithms

- Sorting
	- Quicksort, merge sort.

- Searching 
	- Binary vs linear.

- Big O 
	- For space and time.

- Regular expressions
	- O(n), but O(n!) when matching.
	- It's useful to be familiar with basic regex syntax, too.

- Recursion 
	- And why it is rarely used.

- Python
	- List comprehensions and generators [ x for x in range() ].
	- Iterators and generators.
	- Slicing [start:stop:step].
	- Regular expressions.
	- Types (dynamic types), data structures.
	- Pros and cons of Python vs C, Java, etc.
	- Understand common functions very well, be comfortable in the language.

- Data structures
	- Dictionaries / hash tables (array of linked lists, or sometimes a BST).
	- Arrays.
	- Stacks.
	- SQL/tables. 
	- Bigtables.

## Security themed coding challenges

- Cyphers / encryption algorithms 
	- Be able to implement basic cyphers.

- Parse arbitrary logs 
	- Practice text parsing.

- Web scrapers 
	- Another way to practice text parsing.

- Port scanners 
	- Practice parsing network information.

- botnets
	- How would you build ssh botnet.

- Password bruteforcer
- Scrape meta data from PDFs 
- Script to recover deleted items
- A program that looks for malware signatures in binaries / code samples

# Learning tips 

- [Learning How To Learn course on Coursera](https://www.coursera.org/learn/learning-how-to-learn) is amazing and very useful. Take the full course, or read [this summary on Medium](https://medium.com/learn-love-code/learnings-from-learning-how-to-learn-19d149920dc4).

- **Track concepts - "To learn", "Revising", "Done"**
	- Any terms I couldn't easily explain went on to post-its. 
	- One term per post-it. 
	- "To learn", "Revising", "Done" was written on my whiteboard and I moved my post-its between these categories, I attended to this every few days.
	- I looked up terms everyday, and I practiced recalling terms and explaining them to myself every time I remembered I had these interviews coming up (frequently).
	- I carried around a notebook and wrote down terms and explanations. 

- **Target your learning**
	- Think *hard* about what specific team you are going for, what skills do they want? If you aren't sure, then ask someone who will definitely know.

- **Identify your weaknesses.** 
	- If you're weak on coding and you find yourself avoiding it, then spend most of your study time doing that.

- **Read**
	- Read relevant books (you don't have to read back to back).
	- When looking up things online, avoid going more than two referral links deep - this will save you from browser tab hell.

- **Mental health**
	- Take care of your basic needs first - sleep, eat well, drink water, gentle exercise. You know yourself, so do what's best for you.
	- You are more than your economic output, remember to separate your self worth from your paycheque. 
	- See interviews for what they are - they are *not* a measure of you being "good enough".

# Interviewing tips 

- **Ask questions**
	- Questions create thirst for answers.
	- Ask questions to yourself when you’re studying, to the people you are studying with.
	- Questions reveal how you approach problems.
	- Ask your interviewer lots of questions. They often intentionally ask questions with few details.

- **Say what you are thinking**
	- The interviewer can only make an evaluation on your suitability for the job based on the things you *say*. 
	- If you don't say your thought process aloud, then the interviewer doesn't know what you know. 
	- Practice saying everything you know about a topic, even details you think might be irrelevant. 

- **Reduce cognitive load**
	- If the infrastructure is complicated, draw up what you think it looks like. 
	- Write tests and expected output for code you write, test your code against it. 
	- Take notes about the questions so you don't forget important details.

- **Prepare**
	- Prepare questions that you want to ask your interviewers so you don't need to think of them on the spot on the day. Since an interview is also for you to know more about the workplace, I asked questions about the worst part of the job. 
	- Bring some small snacks in a box or container that isn't noisy and distracting. A little bit of sugar throughout the day can help your problem solving abilities. 
	- Stay hydrated - and take a toilet break between every interview if you need to. 

- **Do practice interviews**
	- Do them until it's comfortable and you can easily talk through problems
	- Ask them to give you really hard questions that you definitely don't know how to answer
	- Practice being in the uncomfortable position where you have no idea about the topic you've been asked. Work through it from first principles.
	- Doooo theeeeemmm yes they can be annoying to organise but it is *worth it*.

### Interviewers are potential friends and they want to help you get the job, they are on your side. Let them help you, ask them questions, say everything you know on a topic and *say your thought process out loud*.

