# Useful-git-links

## Priviledge escalation Linux:
LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS <br>
LinEnum: https://github.com/rebootuser/LinEnum<br>
LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester<br>
Linux Smart Enumeration: https://github.com/diego-treitos/linux-smart-enumeration<br>
Linux Priv Checker: https://github.com/linted/linuxprivchecker<br>

Linux vuln exploit: https://gtfobins.github.io/

# Regex
RegEx is an tool for finding patterns, used to validate or search through text

Write your expression between /.../

Operators:
- | logical OR
- () isolate group
    Example: /(Bob|Alice)Jones/g will look for every BobJones or AliceJones in text
- After a group or character:
    - ? appears 0 or 1 times
    - * appears 0 or more times
    - + appears 1 or more times
    - {a,b} appears between a and b times
- \ use special characters
- Character classes:
    - \d any digit
    - \D any NON digit
    - \w any letter character
    - \s spaces, tabs, newlines and Unicode spaces
    - \0 null
    - \n new line
    - \uXXXX unicode character of code XXXX
- . match any character except \n
- [A-Z] custom character sets
- [^LBC] negative custom character sets
- [^] matches any character
- ^ matches the beginning of a line
- $ matches the end of a line
- \A matches the beginning of the string
- \z matches the end of the string
- \Z matches the end of the string unless the string ends with a "\n", in which case it matches just before the "\n"

## Flags

You can add flags /.../<here> to modify the behaviour of your RegEx

- g global : search every occurence
- i case insensitive
- m multiline : matches the start and end of the entire string as well as the start and end of the line
- s single line 
- u unicode : enables support for unicode
