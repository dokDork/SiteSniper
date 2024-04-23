#!/bin/bash

# Verifica che il file di input esista
if [ $# -ne 2 ]; then
    echo "Usage: $0 <input_file> <output_file>"
    exit 1
fi

file_to_write="$2"
# Verifica se il file esiste e lo cancella se presente
if [ -f "$file_to_write" ]; then
    rm "$file_to_write"
fi

# Legge il file di input riga per riga
while IFS= read -r line; do
    # Converte la parola in minuscolo e aggiunge le estensioni richieste
    normal_word=$(echo "$line")
    lowercase_word=$(echo "$line" | tr '[:upper:]' '[:lower:]')
    if [[ "$normal_word" =~ [[:upper:]] ]]; then
      # Se la parola contiene caratteri maiuscoli salvo anche quella nel file di uscita
      echo "www.${normal_word}.com" >> "$file_to_write"
      echo "www.${normal_word}.htb" >> "$file_to_write"
      echo "www.${normal_word}.it" >> "$file_to_write"
      echo "${normal_word}.com" >> "$file_to_write"
      echo "${normal_word}.htb" >> "$file_to_write"
      echo "${normal_word}.it" >> "$file_to_write"
    fi
    echo "www.${lowercase_word}.com" >> "$file_to_write"
    echo "www.${lowercase_word}.htb" >> "$file_to_write"
    echo "www.${lowercase_word}.it" >> "$file_to_write"
    echo "${lowercase_word}.com" >> "$file_to_write"
    echo "${lowercase_word}.htb" >> "$file_to_write"
    echo "${lowercase_word}.it" >> "$file_to_write"

done < "$1"

echo "Output written to $file_to_write"

