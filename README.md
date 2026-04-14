# Control Room

Dashboard Node.js/Express per gestire i processi PM2 senza accesso SSH.

## Requisiti

- Node.js 18+ (22 LTS consigliato per coerenza con le altre webapp)
- PM2 installato e in esecuzione
- Nginx (per reverse proxy e SSL)

**GENERATOR (D&D)**: l’app PHP in `/home/ubuntu/GENERATOR` non è un processo PM2; è comunque elencata in `lib/constants.js` (`WEB_SITES`, `kind: 'php'`) per health check, tabella porte, daily check interno, script `scripts/daily-app-check.sh` / `health-check.sh` e runbook **Recover generator** (reload `php8.3-fpm` + Nginx). Il nome del servizio FPM si sovrascrive con la variabile d’ambiente `CR_PHP_FPM_SERVICE` se usi un’altra versione PHP.

## Setup

### 1. Crea la cartella e installa le dipendenze

```bash
cd /home/ubuntu/control-room
cp .env.example .env
# Modifica .env: imposta SESSION_SECRET con un valore casuale
# Esempio: openssl rand -hex 32
npm install
```

### 2. Configura .env

Il file `.env.example` contiene valori di esempio. In produzione imposta credenziali amministrative forti e un `SESSION_SECRET` casuale:

```bash
openssl rand -hex 32
# Copia l'output in SESSION_SECRET nel .env
```

Configura anche Redis per lo store sessioni (obbligatorio in produzione):

```env
REDIS_URL=redis://127.0.0.1:6379
REDIS_PREFIX=cr:sess:
SESSION_REDIS_REQUIRED=true
```

Installazione Redis (server Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y redis-server redis-tools
sudo systemctl enable redis-server
sudo systemctl restart redis-server
redis-cli ping   # atteso: PONG
```

### 3. Avvia con PM2

Control Room è incluso nella **configurazione PM2 centralizzata** `~/ecosystem.config.js` (porta 3005, max_memory 256M). Per avviare tutte le app del server:

```bash
pm2 start ~/ecosystem.config.js
pm2 save
```

Oppure solo Control Room (se le altre app sono già in esecuzione):

```bash
pm2 restart control-room
# oppure (se non è ancora registrato in PM2):
pm2 start /home/ubuntu/ecosystem.config.js --only control-room
pm2 save
```

### 3.1 (Opzionale) Avvio automatico al reboot

Per far ripartire automaticamente tutti i processi PM2 dopo un reboot del server:

```bash
pm2 startup
# Esegui il comando sudo che PM2 ti mostra
pm2 save
```

### 4. Configura Nginx

La config Nginx usa upstream `control_room_backend` con keepalive. Rate limiting attivo su `/api/`:

```bash
sudo cp /home/ubuntu/control-room/nginx/matteroma.duckdns.conf /etc/nginx/sites-available/
sudo ln -sf /etc/nginx/sites-available/matteroma.duckdns.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Ottieni certificato SSL (Certbot)

```bash
sudo certbot certonly --webroot -w /var/www/html -d matteroma.duckdns.org
```

Poi modifica `/etc/nginx/sites-available/matteroma.duckdns.conf`:
- Decommenta il blocco `server` con `listen 443 ssl`
- Verifica che i path dei certificati siano corretti
- Esegui: `sudo nginx -t && sudo systemctl reload nginx`

## Utilizzo

1. Accedi a `https://matteroma.duckdns.org` (o `http://` se SSL non è ancora configurato)
2. Login con le credenziali amministrative definite nel tuo `.env`
3. Dalla dashboard puoi:
   - **Grafici real-time**: CPU e RAM con scala 0–100%, aggiornati ogni 3 secondi
   - **Aggiorna tutto**: pulsante per refresh di Overview, Processi PM2, Health check e Processi di sistema
   - **Overview server**: uptime, load, RAM, disco, stato Nginx
   - **Azioni globali**: riavvia tutte le webapp, ripristina tutti i processi
   - **Porte in ascolto**: tabella siti con porta backend (3000, 3001, 3002, 3005) e Nginx (80, 443), verificata con `ss` sul server
   - **Health check**: verifica via HTTP le webapp con URL pubblico (Banana Padel, Roma-Buche, Gestione Veicoli, Control Room)
   - **Link rapidi** alle webapp
   - **Processi PM2**: griglia di **card mini-dashboard** (desktop e mobile) con metriche (CPU, RAM, uptime, restart), stato crash loop, badge modulo, azioni Start/Stop/Restart/Flush/Azzera restart; aggiornamento live ogni 3s; link al dettaglio processo e log
   - **Processi di sistema**: top 25 per CPU (nginx, node, systemd, ecc.), tabella ordinabile cliccando sulle colonne (PID, Nome, CPU %, RAM, Utente)
   - **Reload Nginx** (richiede sudoers configurato)
   - **Azioni rapide** (in cima alla dashboard): scorciatoie verso aggiornamento globale, incidenti, impostazioni, Nginx, health check e porte — pensate per l’uso da telefono oltre al menu laterale

### UX log e dettaglio processo

Nella pagina **dettaglio processo** (log PM2 in tempo reale):

- Barra strumenti sopra al terminale: **pausa / riprendi** auto-scroll, **pulisci vista** (solo buffer visivo, non il file log), **copia selezione**, toggle **solo stderr**, **schermo intero** sul riquadro terminale.
- Altezza contenitore ridotta su viewport strette; in fullscreen il terminale occupa l’area utile per leggere meglio da mobile.

### Impostazioni e pagine operative

- **Impostazioni**: in alto, indice **«Vai a»** con link alle sezioni (Redis, notifiche, 2FA, firewall, webhook/PM2, SSH) tramite ancore sulla pagina.
- **Incident Center, Automation, Maintenance, Analytics**: stessa struttura titolo + breve intro; quando non ci sono dati, empty state con suggerimento del passo successivo (es. crea incidente, esegui runbook, carica log).

### Permesso Nginx reload

Se il pulsante "Reload Nginx" non funziona, aggiungi la regola sudoers:

```bash
echo 'ubuntu ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx' | sudo tee /etc/sudoers.d/control-room
sudo chmod 440 /etc/sudoers.d/control-room
```

### Nginx Config Generator

La pagina **Nginx** (menu laterale) permette di generare e applicare configurazioni Nginx per nuovi domini. Per abilitarla, aggiungi le regole sudoers:

```bash
sudo tee /etc/sudoers.d/control-room-nginx << 'EOF'
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/cp /tmp/controlroom-nginx-*.conf /etc/nginx/sites-available/
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/ln -sf /etc/nginx/sites-available/* /etc/nginx/sites-enabled/
ubuntu ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t
ubuntu ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx
ubuntu ALL=(ALL) NOPASSWD: /usr/bin/certbot certonly --nginx -d *
EOF
sudo chmod 440 /etc/sudoers.d/control-room-nginx
```

Per Certbot, opzionalmente imposta `CR_CONTACT_EMAIL` nel `.env` (email per Let's Encrypt).

## Funzionalità

- **Monitoraggio live**: Grafici CPU/RAM (scala 0–100%), **card PM2** (griglia responsive) e tabella processi di sistema con refresh manuale o "Aggiorna tutto"
- **Processi di sistema**: Top 25 per CPU, ordinamento cliccando sulle intestazioni di colonna
- **Editor .env**: Modifica variabili d'ambiente con valori mascherati (Rivela) e backup `.env.bak`
- **Cron Jobs**: Crea e personalizza job pianificati (PM2 restart, backup DB, comandi)
- **Notifiche**: Discord, Slack o Telegram; master globali (crash, loop restart, eccezioni, stderr, runbook, incidenti, security) e **filtri per processo PM2** in Impostazioni (ambito «tutte le app» vs «solo app selezionate», matrice per disattivare tipi per singola app, sincronizzazione elenco da PM2). Con ambito ristretto, anche le notifiche runbook «recover» per singola app rispettano l’elenco. Persistenza in `settings.json` (non committare URL/token in repo)
- **Feedback UI**: toast con icone e durate differenziate; stati **In corso…** / **Salvato ✓** su salvataggio impostazioni e pulsanti di verifica dove applicabile; dashboard e layout con `aria-busy` su azioni lunghe dove previsto
- **Firewall IP**: Whitelist e Panic Mode per restringere l'accesso
- **Nginx Generator**: Form per generare e applicare config per nuovi domini
- **Incident Center**: Gestione incidenti con stato open/ack/resolved e timeline operativa
- **Automation Suite**: Runbook multi-app (soft/full/safe-rollback), batch mode e storico esecuzioni
- **Analytics & Capacity**: KPI operativi, runbook success rate, capacity risk
- **Maintenance & Security**: Session inventory/revoke, log explorer e diagnostica guidata

### Riferimento `settings.json` – notifiche PM2 (operatori)

Oltre a `webhookType`, `webhookUrl`, token Telegram e i flag `notifyOn*` globali, la Control Room persiste:

| Chiave | Tipo | Significato |
|--------|------|-------------|
| `notifyPm2Scope` | `"all"` \| `"onlyListed"` | Con `onlyListed`, solo i processi in `notifyPm2OnlyApps` possono generare notifiche PM2 (exit, loop, eccezione, stderr). Lista vuota = nessuna notifica PM2 di quel tipo. |
| `notifyPm2OnlyApps` | `string[]` | Nomi processo PM2 consentiti quando lo scope è `onlyListed` (max 64 voci, nomi normalizzati). |
| `notifyPm2PerApp` | oggetto | Per ogni nome processo, campi opzionali `crash`, `restartLoop`, `exception`, `stderr`: valore **`false`** disattiva quel tipo per quell’app (i master globali restano il primo filtro). |

Il markup delle card PM2 in dashboard è condiviso tra SSR (partial EJS) e aggiornamento client; suffissi `m`/`d` sugli `id` delle card evitano duplicati tra vista mobile e desktop nello stesso documento.

## Sicurezza

- Non committare mai il file `.env`
- Non usare credenziali di esempio in produzione
- SSL obbligatorio in produzione
- Sessioni in produzione su Redis (`connect-redis`), non su MemoryStore
- Notifiche Discord avanzate con routing per canale (ops/incidents/security), retry e dead-letter log locale
