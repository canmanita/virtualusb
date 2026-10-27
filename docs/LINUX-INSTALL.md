# Linux and Raspberry Pi installation / Installazione su Linux e Raspberry Pi

## Italiano

Il pacchetto è Python puro: **un solo `.deb` vale per amd64, arm64 e armhf** (Raspberry Pi 2/3/4/5 e Zero 2 con
Raspberry Pi OS, Debian, Ubuntu).

```
sudo apt install ./vhserver_<versione>_all.deb
vhserver doctor
```

L'installazione:
* installa le dipendenze di sistema (`python3-usb1`, `python3-zeroconf`, `python3-ifaddr`, `libusb-1.0-0`, `acl`);
* crea l'utente di sistema `vhserver` e un servizio systemd **senza privilegi** (`NoNewPrivileges`, nessuna capability,
  filesystem in sola lettura); l'accesso ai dispositivi USB arriva da una regola udev (`70-vhserver.rules`) che
  aggiunge un ACL per quell'utente, senza togliere i permessi agli altri;
* crea `/etc/vhserver/config.json` (modificabile; vedi sotto), abilita e avvia il servizio;
* aggiunge il profilo `VHServer` per ufw. **Non modifica il firewall**: se ufw è attivo mostra il comando
  `sudo ufw allow from 192.168.0.0/16 to any app VHServer` da eseguire.

I log sono nel journal: `journalctl -u vhserver -f`. Dopo aver modificato la configurazione:
`sudo systemctl restart vhserver`. Disinstallazione: `sudo apt remove vhserver` (con `purge` anche la configurazione; l'utente di sistema `vhserver` resta, come da policy Debian).

Per il **Raspberry Pi** (compreso il caso in cui c'è già un altro server USB-over-network) vedi [RASPBERRY-PI.md](RASPBERRY-PI.md).

### Password e SSL
```
sudo vhserver password
sudo vhserver tls enable --only
sudo systemctl restart vhserver
```
Aprire anche la porta 7574/tcp se usi SSL (il profilo ufw `VHServer` la include). Dettagli in [SECURITY.md](SECURITY.md). I nickname sono in `/var/lib/vhserver`. Per creare i certificati serve `python3-cryptography` (consigliato dal pacchetto).

### Cosa non viene mai condiviso
* hub USB, tastiere e mouse (`share_hubs` / `share_input` per abilitarli);
* **il dispositivo che porta la rotta predefinita del server**: l'Ethernet integrata di un Raspberry Pi 3 / 4 (è un
  dispositivo USB dietro l'hub) o una chiavetta Ethernet/Wi-Fi USB usata come unica connessione. Cederla a un client
  taglierebbe fuori il server dalla rete.

Nota di sicurezza: la regola udev concede al servizio l'accesso a **tutti** i dispositivi USB, tastiere e mouse inclusi
(non vengono comunque offerti ai client senza `share_input`). Il servizio non ha privilegi e il filtro sugli indirizzi
sorgente resta attivo.

### Altre distribuzioni (Fedora, Arch, ...)
Estrai l'archivio in una cartella di proprietà di root (per esempio `/root`): lo script rifiuta cartelle modificabili da altri.

```
tar xzf vhserver-<versione>-linux.tar.gz && cd vhserver-<versione>-linux && sudo ./install.sh
```
Richiede `python3` con `venv`, la libreria di sistema libusb-1.0 e `acl`; le librerie Python vengono installate da pip in
`/opt/vhserver/venv`.

### Configurazione (`/etc/vhserver/config.json`)
```json
{"name": "Studio", "port": 7575, "allow": ["192.168.0.0/24"], "ignore": ["1d6b:0002"],
 "share_hubs": false, "share_input": false, "mdns": true}
```
Le chiavi sconosciute sono rifiutate. Il nome predefinito è il nome host.

### Raspberry Pi: note
* Alimentazione: i dischi USB assorbono corrente; un hub alimentato evita disconnessioni che il client vede come
  rimozione del dispositivo.
* Sui Raspberry Pi OS più vecchi (Bullseye, Python 3.9) o con librerie di sistema datate, se `vhserver doctor` segnala
  libusb o il servizio non parte, usa l'installer generico (`install.sh`): installa versioni recenti in un virtualenv.
* Auto-Find usa mDNS sulla porta UDP 5353, condivisa con Avahi; non serve fermare Avahi.

## English

The package is pure Python: **one `.deb` serves amd64, arm64 and armhf** (Raspberry Pi 2/3/4/5 and Zero 2 with
Raspberry Pi OS, Debian, Ubuntu).

```
sudo apt install ./vhserver_<version>_all.deb
vhserver doctor
```

It creates the `vhserver` system user and an **unprivileged** systemd service (no capabilities, read-only filesystem);
USB access comes from a udev rule that adds an ACL entry for that user without removing anybody else's access. It writes
`/etc/vhserver/config.json`, enables and starts the service, and ships a ufw application profile `VHServer` but never
changes the firewall (with ufw active it prints `sudo ufw allow from 192.168.0.0/16 to any app VHServer`).

The udev rule grants the service access to every USB device (keyboards and mice are still not offered without `share_input`). Password and SSL: `sudo vhserver password`, `sudo vhserver tls enable --only` (needs `python3-cryptography`; open 7574/tcp; see SECURITY.md). Logs: `journalctl -u vhserver -f`. Never shared: hubs, keyboards and mice (opt in with `share_hubs` / `share_input`),
and the device carrying the server's default route (the Raspberry Pi 3 / 4 onboard Ethernet, or a USB network dongle
that is the only way out). Other distributions: `install.sh` from the tarball (virtualenv in `/opt/vhserver`).

**Tested so far:** the code and package structure on Ubuntu 26.04 / Python 3.14 (WSL) without USB hardware. Not yet
tested on a real Raspberry Pi or with real USB devices on Linux.
