#!/bin/bash

# Verifica se sono stati forniti due parametri
if [ $# -ne 4 ]; then
    echo "Usage: $0 <File with directories list> <target_URL> <BasicAuthN: user> <BasicAuthN: pass>"
    echo "Example:"
    echo "Usage: $0 myFolderList.txt http://10.10.10.10 myUser myPass"
    exit 1
fi

folder_list_file=$1
target_url=$2
webdav_found=0
myUser=$3
myPass=$4

# Verifica se i file esistono
if [ ! -f "$folder_list_file" ]; then
    echo "File $folder_list_file not found."
    exit 1
fi

# Legge il file con la lista delle cartelle e esegue davtest per ciascuna
while IFS= read -r folder || [[ -n "$folder" ]]; do
    echo "Testing $target_url/$folder"
    davtest_output=$(davtest -auth $myUser:$myPass -url "$target_url/$folder" 2>&1)

    # Controlla se davtest ha trovato una cartella WebDAV
    #echo "ris: $davtest_output"
    if [[ "$davtest_output" == *"SUCCEED"* ]]; then
        echo "[OK] WebDAV folder found: $target_url/$folder"
        webdav_found=1
        break
    fi
    if [[ "$davtest_output" == *"Unauthorized"* ]]; then
        echo "[i] possible WebDAV folder found but Basic AuthN needed: $target_url/$folder"
    fi    
done < "$folder_list_file"

# Stampa un messaggio se è stata trovata una cartella WebDAV
if [ $webdav_found -eq 1 ]; then
    echo "[OK] WebDAV folder found. Stopping the scan."
    echo ""
    echo "$davtest_output"
else
    echo "[KO] No WebDAV folders found."
fi

