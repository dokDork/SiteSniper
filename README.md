# SiteSniper
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/siteSniper.png" width="250" height="250">


## Description
**siteSniper** is a script created to automate some phases of a blackbox penetration test. Once the target has been identified, many scripts are prepared which you can decide if and when to execute them simply by pressing ENTER. It uses **tmux** as terminal so it is necessary to know how to use it.
The scripts concern the phase of:
- weaponization: a series of scripts that could be used in the post-exploitation phase on the target machine are loaded onto the attacking Linux machine;
- target fingerprint and exploitation: scripts to collect information on the target (information gathering, service information gathering, OSINT, etc) and scripts that help identify possible exploits;
- web App Site fingerprint: script for analyze site structure, virtual host, etc;
- web App Information gathering: script to implement google dork, CMS analysis, etc;
- web App AuthN bypass: script to implement service brute force, command injection, webDAV analysis, etc.

Once you select a phase, the script will prepare many tmux session with the precompiled command.
To close the tmux session and return to principal menu use the tmux shortcut:
**(CTRL + b) :kill-session**


## Example Usage
`./siteSniper.sh eth0 https://www.example.com` 
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/01.png">


## Command-line parameters

| Parametro | Descrizione                          | Esempio       |
|-----------|--------------------------------------|---------------|
| `-u`      | URL dell'applicazione web da testare | `-u http://example.com` |
| `-a`      | Avvia tutte le fasi di test          | `-a`          |
| `-f`      | Esegue il web app fingerprint        | `-f`          |
| `-g`      | Raccoglie informazioni sul servizio  | `-g`          |

## Installation on Kali Linux

Per installare SiteSniper, seguire questi passaggi:

1. Clonare il repository di SiteSniper:
git clone https://github.com/yourusername/sitesniper.git

2. Navigare nella directory di SiteSniper:
cd sitesniper

3. Rendere lo script eseguibile:

