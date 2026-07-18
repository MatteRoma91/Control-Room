/**
 * Nginx status / reload / config generator — behavior unchanged.
 */
const fs = require('fs').promises;
const { execSync, execFileSync } = require('child_process');

function registerNginxRoutes(app, ctx) {
  const { requireAuth, audit, hasStrongConfirmation, HIGH_RISK_PHRASES } = ctx;

  app.get('/api/nginx-status', requireAuth, (req, res) => {
    try {
      const out = execSync('systemctl is-active nginx 2>/dev/null', { encoding: 'utf8' }).trim();
      res.json({ active: out === 'active' });
    } catch {
      res.json({ active: false });
    }
  });

  app.post('/api/nginx-reload', requireAuth, (req, res) => {
    if (!hasStrongConfirmation(req, 'nginxReload')) {
      return res.status(400).json({ ok: false, error: `Conferma richiesta. Frase: ${HIGH_RISK_PHRASES.nginxReload}` });
    }
    try {
      execSync('sudo /bin/systemctl reload nginx 2>/dev/null', { encoding: 'utf8' });
      audit('nginx_reload', { user: req.session?.user });
      res.json({ ok: true });
    } catch (err) {
      audit('nginx_reload_error', { user: req.session?.user, error: err.message });
      console.error('Nginx reload error:', err);
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get('/nginx', requireAuth, (req, res) => {
    res.render('layout', { contentPartial: 'nginx' });
  });

  app.post('/api/nginx-generate', requireAuth, async (req, res) => {
    let output = [];
    try {
      const { domain, port, ssl } = req.body || {};
      if (!domain || typeof domain !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(domain.trim())) {
        return res.status(400).json({ ok: false, error: 'Dominio non valido' });
      }
      const safeDomain = domain.trim().replace(/\./g, '_');
      const portNum = parseInt(port || 3000, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return res.status(400).json({ ok: false, error: 'Porta non valida' });
      }

      const httpBlock = `# Generato da Control Room - ${domain}
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    location / {
        proxy_pass http://127.0.0.1:${portNum};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
      const tmpPath = `/tmp/controlroom-nginx-${safeDomain}.conf`;
      const destPath = `/etc/nginx/sites-available/${domain}.conf`;
      const backupPath = `/tmp/controlroom-nginx-backup-${safeDomain}-${Date.now()}.conf`;

      await fs.writeFile(tmpPath, httpBlock, 'utf8');
      output.push('File generato: ' + tmpPath);

      try {
        execFileSync('sudo', ['cp', destPath, backupPath], { encoding: 'utf8' });
        output.push('Backup config esistente: ' + backupPath);
      } catch (_) {}
      execFileSync('sudo', ['cp', tmpPath, destPath], { encoding: 'utf8' });
      output.push('Copiato in: ' + destPath);

      execFileSync('sudo', ['ln', '-sf', destPath, `/etc/nginx/sites-enabled/${domain}.conf`], { encoding: 'utf8' });
      output.push('Symlink creato in sites-enabled');

      if (ssl) {
        try {
          const certbotEmail = process.env.CR_CONTACT_EMAIL || `admin@${domain}`;
          execFileSync(
            'sudo',
            ['certbot', 'certonly', '--nginx', '-d', domain, '--non-interactive', '--agree-tos', '--email', certbotEmail],
            { encoding: 'utf8' }
          );
          output.push('Certificato SSL ottenuto con Certbot');
          const httpsBlock = `
# HTTPS - abilitato da Certbot
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${domain};
    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;

    location / {
        proxy_pass http://127.0.0.1:${portNum};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`;
          await fs.writeFile(tmpPath, httpBlock + httpsBlock, 'utf8');
          execFileSync('sudo', ['cp', tmpPath, destPath], { encoding: 'utf8' });
        } catch (certErr) {
          output.push('Certbot fallito (certificati potrebbero esistere già): ' + (certErr.message || certErr));
        }
      }

      execFileSync('sudo', ['nginx', '-t'], { encoding: 'utf8' });
      output.push('nginx -t OK');

      execFileSync('sudo', ['/bin/systemctl', 'reload', 'nginx'], { encoding: 'utf8' });
      output.push('Nginx ricaricato');

      await audit('nginx_generate', { user: req.session?.user, domain, port: portNum, ssl: !!ssl });
      res.json({ ok: true, output: output.join('\n'), rollbackHint: backupPath });
    } catch (err) {
      console.error('Nginx generate error:', err);
      res.status(500).json({ ok: false, error: err.message, output: output.join('\n') });
    }
  });

  app.post('/api/nginx-preview', requireAuth, async (req, res) => {
    try {
      const { domain, port } = req.body || {};
      if (!domain || typeof domain !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(domain.trim())) {
        return res.status(400).json({ ok: false, error: 'Dominio non valido' });
      }
      const portNum = parseInt(port || 3000, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        return res.status(400).json({ ok: false, error: 'Porta non valida' });
      }
      const config = `server {\n    listen 80;\n    listen [::]:80;\n    server_name ${domain.trim()};\n    location / {\n        proxy_pass http://127.0.0.1:${portNum};\n        proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection "upgrade";\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n    }\n}\n`;
      res.json({ ok: true, config });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.post('/api/nginx-rollback', requireAuth, async (req, res) => {
    try {
      const backupPath = String(req.body?.backupPath || '').trim();
      const domain = String(req.body?.domain || '').trim();
      if (!backupPath.startsWith('/tmp/controlroom-nginx-backup-')) {
        return res.status(400).json({ ok: false, error: 'Backup non valido' });
      }
      if (!domain || !/^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({ ok: false, error: 'Dominio non valido' });
      }
      const destPath = `/etc/nginx/sites-available/${domain}.conf`;
      execFileSync('sudo', ['cp', backupPath, destPath], { encoding: 'utf8' });
      execFileSync('sudo', ['nginx', '-t'], { encoding: 'utf8' });
      execFileSync('sudo', ['/bin/systemctl', 'reload', 'nginx'], { encoding: 'utf8' });
      await audit('nginx_rollback', { user: req.session?.user, domain, backupPath });
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });
}

module.exports = { registerNginxRoutes };
