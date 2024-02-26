# SiteSniper
<img src="https://github.com/dokDork/red-team-penetration-test-script/raw/main/siteSniper.png" width="200" height="200">


## Descrizione Generale

SiteSniper è uno script di penetration testing progettato per automatizzare le fasi di weaponization, web app fingerprint e web app service information gathering. Utilizzando tecniche avanzate di scanning e exploit, SiteSniper aiuta i penetration tester a identificare e sfruttare vulnerabilità in applicazioni web.

## Utilizzo

Per utilizzare SiteSniper, eseguire lo script dalla riga di comando con i seguenti parametri:
./sitesniper.sh [opzioni]


### Parametri

| Parametro | Descrizione                          | Esempio       |
|-----------|--------------------------------------|---------------|
| `-u`      | URL dell'applicazione web da testare | `-u http://example.com` |
| `-a`      | Avvia tutte le fasi di test          | `-a`          |
| `-f`      | Esegue il web app fingerprint        | `-f`          |
| `-g`      | Raccoglie informazioni sul servizio  | `-g`          |

## Installazione

Per installare SiteSniper, seguire questi passaggi:

1. Clonare il repository di SiteSniper:
git clone https://github.com/yourusername/sitesniper.git

2. Navigare nella directory di SiteSniper:
cd sitesniper

3. Rendere lo script eseguibile:

