#!/bin/bash

# contiene:
# - le funzioni comuni
# - la richiesta dei parametri utente
# - la creazione delle cartelle di progetto
source "common.sh"

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


