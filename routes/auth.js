/**
 * Auth routes (login / 2FA / logout) — behavior unchanged.
 */
function registerAuthRoutes(app, ctx) {
  const {
    AUTH_USER,
    AUTH_PASSWORD,
    loginLimiter,
    login2FALimiter,
    loadSettings,
    audit,
    speakeasy,
  } = ctx;

  app.get('/login', (req, res) => {
    if (req.session?.user) return res.redirect('/');
    res.render('login', {
      error: req.query.error === '1',
      rateLimited: req.query.rateLimited === '1',
    });
  });

  app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body || {};
    if (username === AUTH_USER && password === AUTH_PASSWORD) {
      const settings = await loadSettings();
      if (settings.totpEnabled && settings.totpSecret) {
        req.session.pending2FA = username;
        req.session.pending2FATime = Date.now();
        return res.redirect('/login/2fa');
      }
      req.session.user = username;
      await audit('login', { user: username });
      return res.redirect('/');
    }
    await audit('login_fail', { reason: 'invalid_credentials' });
    res.redirect('/login?error=1');
  });

  app.get('/login/2fa', (req, res) => {
    if (req.session?.user) return res.redirect('/');
    if (!req.session?.pending2FA) return res.redirect('/login');
    res.render('login-2fa', {
      error: req.query.error === '1',
      rateLimited: req.query.rateLimited === '1',
    });
  });

  app.post('/login/2fa', login2FALimiter, async (req, res) => {
    const username = req.session?.pending2FA;
    if (!username) return res.redirect('/login');
    const { code } = req.body || {};
    const settings = await loadSettings();
    if (!settings.totpSecret || !code || code.length !== 6) {
      return res.redirect('/login/2fa?error=1');
    }
    const valid = speakeasy.totp.verify({
      secret: settings.totpSecret,
      encoding: 'base32',
      token: code.trim(),
      window: 1,
    });
    if (valid) {
      req.session.user = username;
      delete req.session.pending2FA;
      delete req.session.pending2FATime;
      await audit('login', { user: username, mfa: true });
      return res.redirect('/');
    }
    await audit('login_fail', { reason: 'invalid_2fa' });
    res.redirect('/login/2fa?error=1');
  });

  app.post('/logout', (req, res) => {
    const user = req.session?.user;
    req.session.destroy(() => {
      if (user) audit('logout', { user });
      res.redirect('/login');
    });
  });
}

module.exports = { registerAuthRoutes };
