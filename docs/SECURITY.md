# Password, nickname and SSL / Password, nickname e SSL

## Italiano

### In breve
| Cosa | A cosa serve | Comando |
|---|---|---|
| **Password** | chi non la conosce non può usare (né rinominare) il dispositivo | `vhserver password` |
| **SSL** | cifra tutto il traffico (dati delle chiavette e password) e verifica che il server sia il tuo | `vhserver tls enable` |
| **Nickname** | un nome scelto da te per il dispositivo, uguale su tutti i client | dal client, o `DEVICE RENAME` |

Per un uso fuori casa (lavoro) la combinazione consigliata è: **password + SSL esclusivo + elenco indirizzi ammessi**:

```
vhserver password
vhserver tls enable --only
```
e in `config.json` `"allow": ["192.168.0.0/24"]` (o la tua rete aziendale / Tailscale `100.64.0.0/10`). Poi riavvia il servizio.
I comandi vanno eseguiti da **terminale amministratore** (Windows) o con **sudo** (Linux).

### Password
* `vhserver password` chiede la password due volte (8–127 caratteri) e salva solo un hash (scrypt) in `config.json`.
  `--device 346d:5678:SERIALE` la imposta per un solo dispositivo; `--clear` la toglie. La chiave del dispositivo
  compare nel log (`[key ...]`) quando lo colleghi.
* Il client chiede la password con la finestra *Please enter the password to use this device* (può ricordarla).
  Da riga di comando: `vhui64 -t "USE,<indirizzo>,<password>"`.
* Dopo **5 password sbagliate in 5 minuti** quell'indirizzo è bloccato per 60 secondi.
* La password protegge l'uso e il cambio di nickname; l'elenco dei dispositivi resta visibile.
* **Limite del protocollo:** il client non invia la password ma il suo **MD5** (32 cifre esadecimali). Quel valore *è*
  la credenziale: chi legge il traffico può riusarla. Per questo, fuori da reti fidate, abilita anche SSL.
* Nel server originale la password è usata solo dallo script *ClientAuthorization* (funzione a pagamento). Qui è
  un'implementazione indipendente: nessun controllo di licenza dell'originale viene aggirato.

### Nickname
Clic destro sul dispositivo → *Edit Device Nickname* (oppure `DEVICE RENAME,<indirizzo>,<nome>`). Il nome è conservato
dal server (`nicknames.json`: Windows `C:\ProgramData\VHServer`, Linux `/var/lib/vhserver`) e vale per tutti i client.
Se il dispositivo ha una password serve averla inserita. `"allow_rename": false` nel file di configurazione lo vieta.

### SSL
`vhserver tls enable` crea una **CA privata** e un certificato del server in `tls\` (accanto a `config.json`) e attiva la
porta **7574**; `--only` spegne la porta in chiaro 7575. Comandi: `tls status`, `tls disable`, `tls client NOME`
(certificato client, richiesto da tutti i client da quel momento).

**Su ogni client** serve il file `ca.pem` (la CA del server, mai `ca.key`):
1. nel client: clic destro su *USB Servers* → *Advanced Settings* → *Certificate Authority File* → `ca.pem`;
2. riavvia il client. Il client non controlla il nome host, solo che il certificato sia firmato da quella CA.

Il client trova i server SSL con **Auto-Find** (servizio `_ssl_vhusb._tcp`, istanza *"<nome> (SSL)"*); un hub inserito a mano
usa la porta in chiaro. Verificato con il client ufficiale 6.0.3 (TLS 1.2, connessione `secure="true"`).

> Se modifichi a mano `vhui.ini`, scrivi il percorso con **barre normali** (`C:/Users/me/ca.pem`): con i backslash il
> client lo legge male e non si collega.

Il certificato dura 5 anni e la CA 10; `vhserver doctor` avvisa 30 giorni prima. `tls enable --force` rigenera **anche la
CA**: i client vanno aggiornati con il nuovo `ca.pem`.

## English

| What | Why | Command |
|---|---|---|
| **Password** | whoever does not know it cannot use (or rename) the device | `vhserver password` |
| **SSL** | encrypts all traffic (stick data and the password) and proves the server is yours | `vhserver tls enable` |
| **Nickname** | a name you choose for the device, the same on every client | from the client, or `DEVICE RENAME` |

For use away from home the recommended combination is **password + SSL only + an allow-list of source networks**:
`vhserver password`, `vhserver tls enable --only`, `"allow": ["192.168.0.0/24"]` in `config.json`, then restart the
service. Run the commands from an **administrator terminal** (Windows) or with **sudo** (Linux).

* **Password.** `vhserver password` asks twice (8-127 characters) and stores only a scrypt hash. `--device KEY` sets one
  for a single device (the key is logged as `[key ...]` when the device is plugged in), `--clear` removes it. The client
  shows *Please enter the password to use this device* (and can remember it); on the command line use
  `USE,<address>,<password>`. After 5 wrong passwords in 5 minutes an address is locked out for 60 s. **Protocol
  limit:** the stock client sends the **MD5** of the password, and that value is the credential, so anyone who can
  read the traffic can replay it: use SSL on networks you do not fully trust. The original server only honours
  passwords through its paid *ClientAuthorization* script; this is an independent implementation and bypasses nothing.
* **Nickname.** Right-click the device in the client, *Edit Device Nickname*. The server keeps it (`nicknames.json`) for
  every client; a password-protected device needs the password; `"allow_rename": false` forbids renaming.
* **SSL.** `vhserver tls enable` creates a private CA and a server certificate under `tls/` and opens port 7574
  (`--only` also closes the plain port 7575); `tls status`, `tls disable`, `tls client NAME` (require client
  certificates). Give **`ca.pem`** (never `ca.key`) to every client: right-click *USB Servers* -> *Advanced Settings* ->
  *Certificate Authority File*, then restart the client. The client finds SSL servers through Auto-Find
  (`_ssl_vhusb._tcp`, instance *"<name> (SSL)"*) and does not check host names. Verified with client 6.0.3. If you edit
  `vhui.ini` by hand use forward slashes in the path. The certificate lasts 5 years, the CA 10; `tls enable --force`
  regenerates the CA too, so clients need the new `ca.pem`.
