# Karma Query API Nmap NSE Script

Nmap NSE Script to query the Karma API.

With this script, nmap automatically retrieves the reputation and other data about the scanned IP addresses

## Example Usage:

```
$ nmap -sn -Pn --script karma --script-args karma.apikey=$KARMA_APIKEY 181.64.192.163

Starting Nmap 7.12 ( https://nmap.org ) at 2016-05-05 20:05 ART
Nmap scan report for 181.64.192.163
Host is up.

Host script results:
| karma: 
|   blacklists: uceprotect.level3,uceprotect.level1,uceprotect.level2,spamhaus.pbl,sorbs.spam,bad.psky.me
|   asn: 6147
|   cc: PE
|   country: Peru
|   status: blacklisted
|   rir: LACNIC
|_  asname: Telefonica del Peru S.A.A.,PE
```

## API KEY

To use the script, you must have a valid Karma API Key.

You can obtain a free API Key on [https://karma.securetia.com](https://karma.securetia.com)

The API Key can be specified as a parameter "karma.apikey" (like the example above).

Also, can be defined has an environment variable (KARMA_APIKEY).

