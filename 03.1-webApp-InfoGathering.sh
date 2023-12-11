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

# WEB nmap whois
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:1 -n 'WEB nmap whois'
tmux split-window -v -t PT:1.0  
tmux split-window -v -t PT:1.1 
tmux split-window -v -t PT:1.2 
tmux split-window -v -t PT:1.5 
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
tmux send-keys -t PT:2.0 "sslscan http://$domain"
tmux send-keys -t PT:2.1 "# certificate analysis" Enter
tmux send-keys -t PT:2.1 "openssl s_client -connect $site:443 </dev/null 2>/dev/null | openssl x509 -out $site.crt; echo \"Certificato scaricato: $site.crt\" # get certificate info"
cd $folderProject


# WEB google dork
cd $folderProjectWebInfo
# Layout
tmux new-window -t PT:3 -n 'WEB google dork'
tmux split-window -v -t PT:3.0
# Esecuzione dei comandi nelle sottofinestre
tmux send-keys -t PT:3.0 "# google dork" Enter
tmux send-keys -t PT:3.0 "xdg-open \"https://duckduckgo.com/?q=site:$domain filetype:php\" & xdg-open \"https://duckduckgo.com/?q=site:$domain intitle:\"\"index of\"\" \"\"parent directory\"\"\" & xdg-open \"https://duckduckgo.com/?q=site:$domain –site:www.$domain\" & xdg-open \"https://duckduckgo.com/?q=site:pastebin.com $domain\" & xdg-open \"https://duckduckgo.com/?q=site:github.com $domain\" & xdg-open \"https://duckduckgo.com/?q=site:pastebin.com intext:$domain\" # google dork"
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
tmux send-keys -t PT:5.0 "nmap –sV --script=ssl-heartbleed $ip"
tmux send-keys -t PT:5.1 "# attack target by means of heartbleed" Enter
tmux send-keys -t PT:5.1 "msfconsole -q -x \"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOSTS $ip;set RPORT 443;set VERBOSE true;exploit;exit -y\""
cd $folderProject


# Attivazione della modalità interattiva
tmux -2 attach-session -t PT


