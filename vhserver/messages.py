"""End-user texts of the installer and diagnostics: Italian first, English as the second language."""
from __future__ import annotations

import os

ITALIAN, ENGLISH = "it", "en"
LANG_ENV = "VHSERVER_LANG"
_LANGID_ITALIAN = 0x10  # primary language id of Italian

TEXTS: dict[str, dict[str, str]] = {
    "pw_prompt": {"it": "Nuova password: ", "en": "New password: "},
    "pw_confirm": {"it": "Ripeti la password: ", "en": "Repeat the password: "},
    "pw_mismatch": {"it": "Le due password non coincidono.", "en": "The two passwords do not match."},
    "pw_short": {"it": "La password deve avere almeno 8 caratteri.", "en": "The password must have at least 8 characters."},
    "pw_long": {"it": "La password può avere al massimo 127 byte.", "en": "The password can have at most 127 bytes."},
    "pw_set": {"it": "Password impostata per {target}.", "en": "Password set for {target}."},
    "pw_cleared": {"it": "Password rimossa per {target}.", "en": "Password removed for {target}."},
    "pw_all_devices": {"it": "tutti i dispositivi", "en": "all devices"},
    "restart_hint": {"it": "Riavvia il server per applicare la modifica (Windows: schtasks /End /TN VHServer e poi "
                           "schtasks /Run /TN VHServer; Linux: sudo systemctl restart vhserver).",
                     "en": "Restart the server to apply the change (Windows: schtasks /End /TN VHServer then "
                           "schtasks /Run /TN VHServer; Linux: sudo systemctl restart vhserver)."},
    "no_permission": {"it": "Permesso negato: esegui il comando come amministratore (Linux: con sudo).",
                      "en": "Permission denied: run the command as administrator (Linux: with sudo)."},
    "config_error": {"it": "Errore di configurazione: {error}", "en": "Configuration error: {error}"},
    "tls_enabled": {"it": "SSL attivo. Certificato della CA da dare ai client: {ca}\nNel client: USB Servers -> "
                          "Advanced Settings -> Certificate Authority File, poi aggiungi il server sulla porta {port}.",
                    "en": "SSL enabled. CA certificate to give to the clients: {ca}\nIn the client: USB Servers -> "
                          "Advanced Settings -> Certificate Authority File, then add the server on port {port}."},
    "tls_plain_off": {"it": "La porta in chiaro è disattivata: i client devono usare SSL.",
                      "en": "The plain port is switched off: clients must use SSL."},
    "tls_disabled": {"it": "SSL disattivato (i certificati restano su disco).",
                     "en": "SSL disabled (the certificates stay on disk)."},
    "tls_status_off": {"it": "SSL non attivo.", "en": "SSL is not enabled."},
    "tls_status_on": {"it": "SSL attivo, certificato valido ancora {days} giorni (porta {port}); CA: {ca}",
                      "en": "SSL enabled, certificate valid for {days} more days (port {port}); CA: {ca}"},
    "tls_status_bad": {"it": "SSL configurato ma il certificato non è leggibile: {path}",
                       "en": "SSL is configured but the certificate cannot be read: {path}"},
    "tls_needs_enable": {"it": "Attiva prima SSL: vhserver tls enable", "en": "Enable SSL first: vhserver tls enable"},
    "tls_client_made": {"it": "Certificato client creato: {cert} (chiave: {keyfile}). Importalo nel client "
                              "(SSL Client Certificate).",
                        "en": "Client certificate created: {cert} (key: {keyfile}). Import it in the client "
                              "(SSL Client Certificate)."},
    "tls_step_ok": {"it": "SSL attivato: certificati creati", "en": "SSL enabled: certificates created"},
    "tls_step_failed": {"it": "Attivazione SSL non riuscita (vedi il messaggio sopra)",
                        "en": "Enabling SSL failed (see the message above)"},
    "pw_step_ok": {"it": "Password impostata", "en": "Password set"},
    "pw_step_failed": {"it": "Impostazione della password non riuscita (almeno 8 caratteri)",
                       "en": "Setting the password failed (at least 8 characters)"},
    "pw_port_key": {"it": "Attenzione: questo dispositivo non ha un seriale, la chiave dipende dalla porta USB: se lo sposti "
                          "perde la password. Meglio una password per tutti i dispositivi.",
                    "en": "Warning: this device has no serial number, so its key depends on the USB port: if you move it, "
                          "it loses its password. A password for all devices is safer."},
    "need_admin": {"it": "Servono i privilegi di amministratore: riapri il terminale come amministratore.",
                   "en": "Administrator rights are required: reopen the terminal as administrator."},
    "bad_name": {"it": "Il nome del server deve avere da 1 a 64 byte (UTF-8).",
                 "en": "The server name must be 1 to 64 bytes (UTF-8)."},
    "bad_port": {"it": "La porta deve essere un numero tra 1 e 65535.",
                 "en": "The port must be a number between 1 and 65535."},
    "dir_secured": {"it": "Cartella dati protetta (solo SYSTEM e Amministratori): {path}",
                    "en": "Data folder locked down (SYSTEM and Administrators only): {path}"},
    "dir_reset": {"it": "La cartella dati esisteva già con un proprietario non fidato: protetta e svuotata ({path}).",
                  "en": "The data folder already existed under an untrusted owner: locked down and emptied ({path})."},
    "dir_unsafe": {"it": "Cartella dati non sicura o non proteggibile: {path}. Eliminala e riprova.",
                   "en": "Data folder is unsafe or cannot be locked down: {path}. Delete it and retry."},
    "need_packaged": {"it": "L'installazione richiede il programma impacchettato (vhserver.exe), non lo script.",
                      "en": "Installing needs the packaged program (vhserver.exe), not the script."},
    "config_written": {"it": "Configurazione creata in {path}", "en": "Configuration written to {path}"},
    "config_kept": {"it": "Configurazione esistente mantenuta: {path}", "en": "Existing configuration kept: {path}"},
    "config_failed": {"it": "Impossibile scrivere la configurazione: {error}",
                      "en": "Cannot write the configuration: {error}"},
    "firewall_ok": {"it": "Regole firewall create (solo rete locale e Tailscale)",
                    "en": "Firewall rules created (local network and Tailscale only)"},
    "firewall_failed": {"it": "Regola firewall non creata: {rule}", "en": "Firewall rule not created: {rule}"},
    "task_ok": {"it": "Avvio automatico configurato (attività pianificata 'VHServer', account SYSTEM)",
                "en": "Automatic start configured (scheduled task 'VHServer', SYSTEM account)"},
    "task_failed": {"it": "Attività pianificata non creata: {error}", "en": "Scheduled task not created: {error}"},
    "listening_ok": {"it": "Il server è in ascolto sulla porta {port}", "en": "The server is listening on port {port}"},
    "listening_failed": {"it": "Il server non risponde sulla porta {port}: esegui 'vhserver doctor'",
                         "en": "The server does not answer on port {port}: run 'vhserver doctor'"},
    "removed_task": {"it": "Avvio automatico rimosso", "en": "Automatic start removed"},
    "removed_rules": {"it": "Regole firewall rimosse", "en": "Firewall rules removed"},
    "recovered": {"it": "Dispositivi riportati al driver originale: {count}",
                  "en": "Devices returned to their original driver: {count}"},
    "purged": {"it": "Dati e log eliminati", "en": "Data and logs deleted"},
    "doctor_admin": {"it": "Privilegi di amministratore", "en": "Administrator rights"},
    "doctor_admin_fix": {"it": "Avvia il programma come amministratore (necessario per cambiare driver).",
                         "en": "Run as administrator (needed to switch drivers)."},
    "doctor_libusb": {"it": "Libreria USB (libusb)", "en": "USB library (libusb)"},
    "doctor_config": {"it": "File di configurazione", "en": "Configuration file"},
    "doctor_task": {"it": "Avvio automatico (attività 'VHServer')", "en": "Automatic start (task 'VHServer')"},
    "doctor_task_fix": {"it": "Esegui 'vhserver install' da amministratore.",
                        "en": "Run 'vhserver install' as administrator."},
    "doctor_rules": {"it": "Regole firewall in ingresso", "en": "Inbound firewall rules"},
    "doctor_rules_fix": {"it": "Esegui 'vhserver install' da amministratore per ricrearle.",
                         "en": "Run 'vhserver install' as administrator to recreate them."},
    "doctor_block": {"it": "Nessuna regola firewall di blocco per il programma",
                     "en": "No firewall block rule for the program"},
    "doctor_block_fix": {"it": "Una regola di blocco vince su ogni regola di consenso. Rimuovila: {rules}",
                         "en": "A block rule overrides any allow rule. Remove it: {rules}"},
    "doctor_profile": {"it": "Profilo di rete privato", "en": "Private network profile"},
    "doctor_profile_fix": {"it": "La rete '{alias}' è Pubblica: il firewall la tratta come non fidata. "
                                 "Se è la tua rete di casa: Set-NetConnectionProfile -InterfaceAlias \"{alias}\" "
                                 "-NetworkCategory Private  (oppure reinstalla con --allow-public).",
                           "en": "Network '{alias}' is Public, so the firewall treats it as untrusted. If it is your "
                                 "home network: Set-NetConnectionProfile -InterfaceAlias \"{alias}\" "
                                 "-NetworkCategory Private  (or reinstall with --allow-public)."},
    "doctor_port": {"it": "Server in ascolto sulla porta {port}", "en": "Server listening on port {port}"},
    "doctor_port_fix": {"it": "Avvia l'attività: schtasks /Run /TN VHServer  (oppure vedi il log).",
                        "en": "Start the task: schtasks /Run /TN VHServer  (or check the log)."},
    "doctor_service": {"it": "Servizio systemd 'vhserver' attivo", "en": "systemd service 'vhserver' is active"},
    "doctor_service_fix": {"it": "sudo systemctl enable --now vhserver  (log: journalctl -u vhserver -e)",
                           "en": "sudo systemctl enable --now vhserver  (log: journalctl -u vhserver -e)"},
    "doctor_usb": {"it": "Accesso ai dispositivi USB per il servizio", "en": "USB device access for the service"},
    "doctor_usb_fix": {"it": "Regola udev o utente 'vhserver' mancanti: reinstalla il pacchetto, poi "
                             "sudo udevadm control --reload && sudo udevadm trigger",
                       "en": "udev rule or 'vhserver' user missing: reinstall the package, then "
                             "sudo udevadm control --reload && sudo udevadm trigger"},
    "doctor_firewall": {"it": "Firewall: porte {port}/tcp e 5353/udp raggiungibili dalla rete locale",
                        "en": "Firewall: ports {port}/tcp and 5353/udp reachable from the local network"},
    "doctor_firewall_ufw": {"it": "ufw è attivo: sudo ufw allow from 192.168.0.0/16 to any port {port},{ssl_port} proto tcp "
                                  "&& sudo ufw allow from 192.168.0.0/16 to any port 5353 proto udp",
                            "en": "ufw is active: sudo ufw allow from 192.168.0.0/16 to any port {port} proto tcp "
                                  "&& sudo ufw allow from 192.168.0.0/16 to any port 5353 proto udp"},
    "doctor_firewall_firewalld": {"it": "firewalld è attivo: sudo firewall-cmd --permanent --add-port={port}/tcp --add-port={ssl_port}/tcp "
                                        "--add-port=5353/udp && sudo firewall-cmd --reload",
                                  "en": "firewalld is active: sudo firewall-cmd --permanent --add-port={port}/tcp "
                                        "--add-port=5353/udp && sudo firewall-cmd --reload"},
    "doctor_tls_off": {"it": "SSL non attivo (traffico non cifrato)", "en": "SSL is off (traffic is not encrypted)"},
    "doctor_tls_off_pw_fix": {"it": "La password viaggia come hash riutilizzabile: attiva SSL con 'vhserver tls enable'.",
                              "en": "The password travels as a reusable hash: enable SSL with 'vhserver tls enable'."},
    "doctor_tls_on": {"it": "SSL attivo, certificato valido ancora {days} giorni", "en": "SSL is on, certificate valid for {days} more days"},
    "doctor_tls_soon": {"it": "Il certificato scade tra {days} giorni: rigeneralo con 'vhserver tls enable --force' e "
                              "ridai ca.pem ai client.",
                        "en": "The certificate expires in {days} days: renew it with 'vhserver tls enable --force' and "
                              "give ca.pem to the clients again."},
    "doctor_tls_expired": {"it": "SSL: certificato scaduto", "en": "SSL: certificate expired"},
    "doctor_tls_missing": {"it": "SSL: file del certificato mancante", "en": "SSL: certificate file missing"},
    "doctor_tls_missing_fix": {"it": "Manca {path}: ricrea i certificati con 'vhserver tls enable --force'.",
                               "en": "{path} is missing: recreate the certificates with 'vhserver tls enable --force'."},
    "doctor_tls_unreadable": {"it": "SSL: impossibile leggere il certificato", "en": "SSL: cannot read the certificate"},
    "doctor_tls_unreadable_fix": {"it": "Controlla {path} (e che il pacchetto cryptography sia installato).",
                                  "en": "Check {path} (and that the cryptography package is installed)."},
    "doctor_pw_set": {"it": "Password impostata", "en": "A password is set"},
    "doctor_pw_none": {"it": "Nessuna password: chiunque nella rete consentita può usare i dispositivi",
                       "en": "No password: anybody on the allowed networks can use the devices"},
    "doctor_usb_acl": {"it": "Il servizio non può scrivere sui dispositivi USB collegati",
                       "en": "The service cannot write to the USB devices that are plugged in"},
    "doctor_usb_acl_fix": {"it": "Applica la regola udev ai dispositivi già presenti: sudo udevadm trigger --subsystem-match=usb --action=change (oppure scollega e ricollega il dispositivo).",
                           "en": "Apply the udev rule to devices that are already plugged in: sudo udevadm trigger --subsystem-match=usb --action=change (or unplug and replug the device)."},
    "doctor_conflict": {"it": "La porta {port} è già occupata da un altro programma",
                        "en": "Port {port} is already used by another program"},
    "doctor_conflict_fix": {"it": "Probabilmente un altro server USB-over-network: scegli un'altra porta ('port' in /etc/vhserver/config.json) e riavvia, oppure ferma l'altro server.",
                            "en": "Probably another USB-over-network server: pick another port ('port' in /etc/vhserver/config.json) and restart, or stop the other server."},
    "doctor_pending": {"it": "Nessun dispositivo lasciato su WinUSB", "en": "No device left on WinUSB"},
    "doctor_pending_fix": {"it": "Verranno ripristinati al prossimo avvio del server: {ids}",
                           "en": "They will be restored the next time the server starts: {ids}"},
    "doctor_mdns": {"it": "Indirizzo annunciato in rete (Auto-Find): {address}",
                    "en": "Address announced on the network (Auto-Find): {address}"},
    "doctor_mdns_fix": {"it": "Nessuna rete con multicast trovata: i client dovranno usare l'indirizzo manuale.",
                        "en": "No multicast-capable network found: clients will need the manual address."},
}


def language() -> str:
    forced = os.environ.get(LANG_ENV, "").lower()
    if forced in (ITALIAN, ENGLISH):
        return forced
    if os.name == "nt":
        try:
            import ctypes

            if ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0xFF != _LANGID_ITALIAN:
                return ENGLISH
        except (OSError, AttributeError):
            pass
    return ITALIAN


def text(key: str, **values: object) -> str:
    return TEXTS[key][language()].format(**values)
