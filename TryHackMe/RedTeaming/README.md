# Command and Control (C2)

## Introduction

Command and Control (C2) is a central component of a red team operation. It is the mechanism by which the red team can communicate with the compromised systems. This is a critical component of the operation as it allows the red team to execute commands, exfiltrate data, maintain persistence on the target network and often help in lateral movement.

## C2 servers

Server to which the compromised systems send beacons to, and from which the red team can send commands to the compromised systems. A listener is running on the C2 server which listens for incoming connections from the compromised systems.

### Jitter

Jitter is a random delay added to the beaconing interval. This is done to avoid detection by the defenders.

### Staged vs Stageless payloads

Staged = Payload is split into multiple parts, and each part is sent separately. This is useful when the payload is large and cannot be sent in one go. First portion is called a Dropper.

Stageless = Entire payload is sent in one go.

### C2 Modules 

C2 servers often have multiple modules that can be used to interact with the compromised systems. Some of the common modules are:
- Post exploitation modules
- Pivoting modules

## Domain Fronting

Domain fronting is a technique used to hide the true destination of the C2 server. It uses a CDN (Content Delivery Network) to redirect the traffic to the C2 server. This is done to avoid detection by the defenders.

## C2 Profiles

C2 profiles are configurations that define how the C2 server should behave when receiving connections from the compromised systems or from other non compromised systems. These profiles can be used to define the following:
- How the C2 server should behave when receiving connections from the compromised systems (send and receive commands, exfiltrate data, etc.)
- How the C2 server should behave when receiving connections from other non compromised systems (redirect to a decoy server, etc.)

## C2 Frameworks

C2 frameworks are tools that can be used to create and manage C2 servers. Some of the popular C2 frameworks are:
Free:
- Metasploit
- Armitage (GUI for Metasploit)
- Empire/Starkiller (PowerShell based)
- Covenant (for post exploitation and lateral movement)
- Sliver 
Paid:
- Cobalt Strike (very popular)
- Brute Ratel

