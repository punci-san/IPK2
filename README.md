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
__tcp_porty__ sú tcp porty ktoré chce užívatel preskenovať zapisujú sa `1,2,3` alebo rozsahom `1-3`,
__udp_porty__ sú udp porty ktoré chce užívatel preskenovať zapisujú sa `1,2,3` alebo rozsahom `1-3`,
__ip adresa__ je adresa servera ktorý chce užívateľ preskenovať, môže byť zadaná aj ako názov domény.


# Omezenie/rozšírenie

Skener vie pracovať aj pomocou IPV6 stačí len zvoliť správny server ktorý tento typ skenu dovoluje.
