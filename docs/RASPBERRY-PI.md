# Raspberry Pi

## Italiano

Un solo pacchetto `.deb` (Python puro, `Architecture: all`) vale per Raspberry Pi OS e Debian 12 a 32 e 64 bit.

### Installazione
```
sudo apt install ./vhserver_<versione>_all.deb
sudo vhserver doctor
```
`apt` porta da solo le dipendenze di Bookworm (`python3-usb1`, `python3-zeroconf`, `python3-ifaddr`, `python3-lz4`,
`libusb-1.0-0`, `acl`). `python3-cryptography` serve solo per creare i certificati (`vhserver tls enable`).
Il servizio parte da solo all'accensione; i log sono in `journalctl -u vhserver -f`.

### Se sul Pi c'è già un altro server USB-over-network
L'altro server (`vhusbd*`) e il nostro **non devono condividere gli stessi dispositivi**: il primo che apre una
chiavetta la tiene, l'altro riceve un errore. Il pacchetto lo gestisce così:
* se la porta (7575) è occupata, il servizio viene **abilitato ma non avviato** e l'installazione lo segnala;
* scegli un'altra porta e i dispositivi da escludere in `/etc/vhserver/config.json`
  (vedi `config.example.json` in `/usr/share/doc/vhserver/`):
  `{"port": 7600, "ignore": ["0529:0003", "346d:5678"]}`, poi `sudo systemctl start vhserver`;
* sul client aggiungi l'hub `indirizzo-del-pi:7600`.
Per avere nomi e firewall coerenti conviene lasciare **all'altro server** i dongle di licenza e usare il nostro per
il resto, oppure spostare tutto sul nostro solo dopo aver provato.

### Cosa il server non offre mai, in automatico
* la **LAN integrata** del Pi 3 / 3B+ / 4 (è un dispositivo USB dietro l'hub: cederla taglierebbe fuori il Pi dalla rete)
  e qualunque scheda di rete USB che porta la rotta predefinita;
* hub, tastiere e mouse (`share_hubs` / `share_input` per abilitarli).

### Consigli
* **Alimentazione:** i dischi e i dongle USB assorbono corrente; un hub alimentato evita disconnessioni che il client vede
  come rimozione del dispositivo.
* **Scheda SD:** il server non scrive sulla SD durante l'uso (log nel journal, nickname in `/var/lib/vhserver`).
* **Prestazioni:** `python3-lz4` (in C) è una dipendenza proprio perché sul Pi la versione in Python puro sarebbe lenta.

### Se il servizio senza privilegi non riesce ad aprire i dispositivi
`sudo vhserver doctor` lo segnala (*Il servizio non può scrivere sui dispositivi USB*). Prima prova:
`sudo udevadm trigger --subsystem-match=usb --action=change` (o scollega e ricollega il dispositivo). Se non basta,
come ripiego esegui il servizio come root: `sudo systemctl edit vhserver` e inserisci
```
[Service]
User=root
Group=root
```
poi `sudo systemctl restart vhserver`.

### Cosa è stato verificato e cosa no
Verificato su un Raspberry Pi 3 Model B Rev 1.2, Debian 12, Python 3.11.2, aarch64, con le librerie di Bookworm
(`python3-usb1` 2.0.1, `python3-zeroconf` 0.47.3, `python3-ifaddr` 0.1.7), eseguendo il server **come root** da cartella
e senza il servizio: elenco dei dispositivi, esclusione dei dongle con `--ignore`, LAN integrata scartata, collegamento e
scollegamento con ripristino del driver (`btusb`), estrazione e reinserimento a caldo, client 5.8.6 via Tailscale.
L'annuncio mDNS è stato controllato contro il codice di zeroconf 0.47.3 (non sul Pi).

**Non ancora verificato sul Pi:** il servizio systemd senza privilegi (utente `vhserver` + regola udev), l'annuncio mDNS
vero, SSL, password con il client 5.8.6, copia di dati con una memoria di massa e la velocità sul Pi 3.

### Disinstallazione
`sudo apt remove vhserver` (con `purge` anche configurazione e nickname; l'utente `vhserver` resta).

## English

One `.deb` (pure Python, `Architecture: all`) serves Raspberry Pi OS and Debian 12, 32 and 64 bit:
`sudo apt install ./vhserver_<version>_all.deb`, then `sudo vhserver doctor`. `apt` brings the Bookworm dependencies
(`python3-usb1`, `python3-zeroconf`, `python3-ifaddr`, `python3-lz4`, `libusb-1.0-0`, `acl`); `python3-cryptography` is
only needed to create certificates.

**Another USB-over-network server on the same Pi:** the two must not share the same devices. If the port (7575) is busy the
service is enabled but not started and the installer says so; set another `port` and an `ignore` list in
`/etc/vhserver/config.json` (see `config.example.json`), then `sudo systemctl start vhserver`, and add the hub
`<pi-address>:7600` in the client.

Never offered automatically: the **onboard Ethernet** of the Pi 3 / 3B+ / 4 (a USB device behind the hub) and any USB network
adapter that carries the default route; hubs, keyboards and mice. If the unprivileged service cannot open devices
(`doctor` says so), run `sudo udevadm trigger --subsystem-match=usb --action=change`; as a last resort run the service as
root with `sudo systemctl edit vhserver` (`[Service] User=root Group=root`).

**Verified** on a Raspberry Pi 3 Model B Rev 1.2, Debian 12, Python 3.11.2, aarch64 with the Bookworm libraries, running
the server as root from a folder: device list, `--ignore`, onboard Ethernet withheld, bind/unbind with driver restore,
hot-plug, client 5.8.6 over Tailscale. mDNS was checked against the zeroconf 0.47.3 code only. **Not yet verified on the
Pi:** the unprivileged systemd service, real mDNS, SSL, password with client 5.8.6, data copy and speed.
