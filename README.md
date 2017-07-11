# Karma Query API Nmap NSE Script

Nmap NSE Script to query the Karma API.

With this script, nmap automatically retrieves the blacklist that contains the scanned IP addresses

## Example Usage:

```
$ nmap -sn -Pn --script karma 181.64.192.163

Starting Nmap 7.12 ( https://nmap.org ) at 2016-05-05 20:05 ART
Nmap scan report for 181.64.192.163
Host is up.

Host script results:
| karma: 
|   hphosts_psh
|   hphosts_emd
|_  hphosts_fsa
```

