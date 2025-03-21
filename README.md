# SiteSniper
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)  
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/siteSniper.png" width="250" height="250">  
  
## Description
**SiteSniper** is a script created to automate some phases of a blackbox penetration test. Once the target has been identified, many scripts are prepared which you can decide if and when to execute them simply by pressing ENTER. It uses **tmux** as terminal so it is necessary to know how to use it.
The scripts concern the phase of:
- weaponization: a series of scripts that could be used in the post-exploitation phase on the target machine are loaded onto the attacking Linux machine;
- target fingerprint and exploitation: scripts to collect information on the target (information gathering, service information gathering, OSINT, etc) and scripts that help identify possible exploits;
- web App Site fingerprint: script for analyze site structure, virtual host, etc;
- web App Information gathering: script to implement google dork, CMS analysis, etc;
- web App AuthN bypass: script to implement service brute force, command injection, webDAV analysis, etc.
Once you select a phase, the script will prepare many tmux session with the precompiled command.

  
## Example Usage
 ```
./siteSniper.sh eth0 https://www.example.com
 ``` 
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/01.png">

select one of the penetration test PHASES you are interested in:
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/02.png">

Once selected the PHASE, scripts will be generated using tmux as terminal.
At this point you can select a specific SUB-PHASE using tmux commands:  
**(CTRL + b) w**  
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/03.png">

once the SUB-PHASE has been selected you will be able to view the commands that have been pre-compiled to analyse the SUB-PHASE. At this point it is possible to selecet and execute a specific command just pressing ENTER:
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/04.png">

When you need to change penetration test PHASE and return to main manu, you need to close the tmux session. To implement this action you need to use the tmux shortcut:  
**(CTRL + b) :kill-session**  
or, if you configure tmux as reported in the Installation section, you can use the shortcut:
**(CTRL + b) (CTRL + n)**  

<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/images/05.png">

  
## Command-line parameters
```
./siteSniper.sh <interface> <target url>
```

| Parameter | Description                          | Example       |
|-----------|--------------------------------------|---------------|
| `interface`      | network interface through which the target is reached | `eth0`, `wlan0`, `tun0`, ... |
| `target url`      | Target URL you need to test          | `http://www.example.com`          |

  
## How to install it on Kali Linux (or Debian distribution)
It's very simple  
```
cd /opt
sudo git clone https://github.com/dokDork/SiteSniper.git
cd SiteSniper 
chmod 755 siteSniper.sh 
./siteSniper.sh 
```
Optional: You can insert a shortcut to move faster through the tool.
```
echo "bind-key C-n run-shell \"tmux kill-session -t #{session_name}\"" >> ~/.tmux.conf
```

