# Control Room

Dashboard Node.js/Express per gestire i processi PM2 senza accesso SSH.

## Requisiti

- Node.js 18+
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
   - **Overview server**: uptime, load, RAM, disco, stato Nginx
   - **Azioni globali**: riavvia tutte le webapp, ripristina tutti i processi
   - **Health check**: verifica che Banana Padel Tour e Roma-Buche rispondano
   - **Link rapidi** alle webapp
   - **Processi PM2**: start, stop, restart singoli, visualizzazione log
   - **Reload Nginx** (richiede sudoers configurato)

### Permesso Nginx reload

Se il pulsante "Reload Nginx" non funziona, aggiungi la regola sudoers:

```bash
echo 'ubuntu ALL=(ALL) NOPASSWD: /bin/systemctl reload nginx' | sudo tee /etc/sudoers.d/control-room
sudo chmod 440 /etc/sudoers.d/control-room
```

## Sicurezza

- Non committare mai il file `.env`
- Modifica le credenziali di default prima dell'uso in produzione
- SSL obbligatorio in produzione
