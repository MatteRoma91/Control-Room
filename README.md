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

Il file `.env.example` contiene già le credenziali predefinite (Matt91 / MattCONTROL1!). Modifica almeno `SESSION_SECRET` con un valore casuale:

```bash
openssl rand -hex 32
# Copia l'output in SESSION_SECRET nel .env
```

### 3. Avvia con PM2

```bash
pm2 start ecosystem.config.js
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
2. Login con **Matt91** / **MattCONTROL1!** (o le credenziali impostate in `.env`)
3. Dalla dashboard puoi:
   - **Grafici real-time**: CPU e RAM con scala 0–100%, aggiornati ogni 3 secondi
   - **Aggiorna tutto**: pulsante per refresh di Overview, Processi PM2, Health check e Processi di sistema
   - **Overview server**: uptime, load, RAM, disco, stato Nginx
   - **Azioni globali**: riavvia tutte le webapp, ripristina tutti i processi
   - **Health check**: verifica che Banana Padel Tour e Roma-Buche rispondano
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
- Modifica le credenziali di default prima dell'uso in produzione
- SSL obbligatorio in produzione
