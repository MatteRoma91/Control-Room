# Route modules

La logica HTTP principale è in [`../server.js`](../server.js). Moduli estratti:

- [`../lib/constants.js`](../lib/constants.js) — ecosistemi PM2, siti web, path file dati/log
- [`../lib/ip-utils.js`](../lib/ip-utils.js) — whitelist IP (normalizzazione, CIDR)

Per aggiungere un nuovo gruppo di route Express, creare un file `nome.js` che esporta `function register(app, ctx)` e montarlo da `server.js` dopo i middleware condivisi.
