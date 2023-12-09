#!/bin/bash

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


