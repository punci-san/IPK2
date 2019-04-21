# Inštalácia a preklad aplikácie

Na preklad projektu je použíty príkaz
```
make
```
ktorým sa program preloží, sú potrebné hlavičkové súbory __netinet__ knižnice a __libcap__.

# Spustenie aplikácie

Applikácia sa spúšta príkazom
```
sudo ./ipk-scan <-i interface> <-pt tcp_porty> <-pu udp_porty> <ip adresa | doména>
```
kde __interface__ značí názov interfacu ktorým sa bude skenovať a z ktorého sa budú packety posielať,
ak port nebude zadaný tak nastáva chyba.

# Omezenie/rozšírenie

Server dovoluje maximálne 200 pripojených socketov v jednom okamihu a dokáže
pracovať aj s ipv6.

Server dokáže reagovať iba na GET požiadavky, a vracať dáta typu text/plain alebo application/json.
