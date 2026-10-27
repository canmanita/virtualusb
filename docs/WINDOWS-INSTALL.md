# Windows installation / Installazione su Windows

## Italiano

1. Esegui `VHServer-Setup-<versione>.exe` (richiede i privilegi di amministratore).
2. Scegli il nome del server e la porta (predefinita 7575). La casella *reti Pubbliche* è disattivata di proposito.
3. Il programma di installazione:
   * crea `C:\ProgramData\VHServer\config.json` (se non esiste già);
   * crea due regole firewall **legate al programma** (TCP della porta scelta e UDP 5353 per Auto-Find), valide solo
     per rete locale e Tailscale, sui profili Privato e Dominio;
   * crea l'attività pianificata `VHServer` (avvio all'accensione, account SYSTEM, riavvio automatico se si ferma);
   * avvia il server e controlla che risponda.
4. Una pagina *Sicurezza* chiede, facoltativamente, una **password**, **SSL** e **solo SSL** (porta in chiaro spenta). Si cambia poi con `vhserver password` e `vhserver tls enable`: vedi [SECURITY.md](SECURITY.md).
5. Nei client compatibili il server compare da solo (Auto-Find); in alternativa aggiungilo a mano con `indirizzo:porta` (un hub manuale usa la porta in chiaro; i server SSL si trovano con Auto-Find).

Dati e log: `C:\ProgramData\VHServer\` (`config.json`, `state.json`, `logs\vhserver.log`).

### Problemi già incontrati (e come li gestisce)

| Problema | Gestione |
|---|---|
| Il portatile non vede il server | regole firewall legate al programma; `doctor` segnala reti *Pubbliche* e regole di **blocco** (che vincono sempre) |
| Windows non monta la chiavetta in remoto | il driver WinUSB viene installato solo mentre un client usa il dispositivo, poi ripristinato |
| Server fermato con la chiavetta in uso | `state.json` ricorda i dispositivi su WinUSB: all'avvio successivo (o alla disinstallazione) tornano al driver originale |
| Auto-Find annuncia indirizzi inutili (WSL, Hyper-V) | viene annunciato solo l'IP della scheda con la rotta predefinita |
| Tastiere e mouse | non vengono mai condivisi (`share_input` nel file di configurazione per abilitarli) |

### Comandi (terminale amministratore)

```
"C:\Program Files\VHServer\vhserver.exe" doctor                 # diagnosi
"C:\Program Files\VHServer\vhserver.exe" install --name Lab     # (re)installa regole e avvio automatico
"C:\Program Files\VHServer\vhserver.exe" uninstall [--purge]    # rimuove attività e regole, ripristina i driver
```

Se la rete di casa è classificata *Pubblica*: `Set-NetConnectionProfile -InterfaceAlias "<scheda>" -NetworkCategory Private`
(oppure `install --allow-public`).

### Configurazione (`config.json`)

```json
{"name": "Studio", "port": 7575, "allow": ["192.168.0.0/24"], "ignore": ["1d6b:0002"],
 "share_hubs": false, "share_input": false, "windows_bind": true, "mdns": true}
```

Le chiavi sconosciute sono rifiutate (un refuso non viene ignorato in silenzio). Dopo una modifica:
`schtasks /End /TN VHServer` e `schtasks /Run /TN VHServer`.

## English

1. Run `VHServer-Setup-<version>.exe` (needs administrator rights).
2. Pick the server name and port (default 7575). The *Public networks* box is off on purpose.
3. The installer writes `C:\ProgramData\VHServer\config.json` (kept if present), creates two **program-scoped** inbound
   firewall rules (TCP on the chosen port, UDP 5353 for Auto-Find; local subnet and Tailscale only; Private and Domain
   profiles), registers the `VHServer` boot task (SYSTEM, restarts on failure) and starts it.
4. An optional *Security* page sets a **password**, **SSL** and **SSL only**; change them later with `vhserver password` / `vhserver tls enable` ([SECURITY.md](SECURITY.md)).
5. Clients find the server by themselves (Auto-Find), or add `address:port` by hand (manual hubs use the plain port; SSL servers are found through Auto-Find).

`vhserver.exe doctor` checks administrator rights, libusb, configuration, task, firewall rules, **blocking rules** (a
block rule overrides every allow rule), Public network profiles, the listening port, devices left on WinUSB and the
address announced for Auto-Find. Devices left on WinUSB after a crash are returned to their own driver at the next
start or by `uninstall`.

The installer is **not code-signed**: Windows SmartScreen will show an "unknown publisher" warning.
