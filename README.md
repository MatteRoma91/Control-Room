# Control Room

Dashboard Node.js/Express per gestire i processi PM2 senza accesso SSH.

## Requisiti

- Node.js 18+ (22 LTS consigliato per coerenza con le altre webapp)
- PM2 installato e in esecuzione
- Nginx (per reverse proxy e SSL)

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
pm2 start control-room
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
   - **Health check**: verifica via HTTP le webapp con URL pubblico (incluso Control Room)
   - **Link rapidi** alle webapp
   - **Processi PM2**: aggiornamento live ogni 3s, start, stop, restart singoli, visualizzazione log
   - **Processi di sistema**: top 25 per CPU (nginx, node, systemd, ecc.), tabella ordinabile cliccando sulle colonne (PID, Nome, CPU %, RAM, Utente)
   - **Reload Nginx** (richiede sudoers configurato)

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

- **Monitoraggio live**: Grafici CPU/RAM (scala 0–100%), tabelle PM2 e processi di sistema con refresh manuale o "Aggiorna tutto"
- **Processi di sistema**: Top 25 per CPU, ordinamento cliccando sulle intestazioni di colonna
- **Editor .env**: Modifica variabili d'ambiente con valori mascherati (Rivela) e backup `.env.bak`
- **Cron Jobs**: Crea e personalizza job pianificati (PM2 restart, backup DB, comandi)
- **Notifiche**: Discord, Slack o Telegram su crash/restart dei processi
- **Firewall IP**: Whitelist e Panic Mode per restringere l'accesso
- **Nginx Generator**: Form per generare e applicare config per nuovi domini

## Sicurezza

- Non committare mai il file `.env`
- Non usare credenziali di esempio in produzione
- SSL obbligatorio in produzione
- Sessioni in produzione su Redis (`connect-redis`), non su MemoryStore
