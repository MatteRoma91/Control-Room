/**
 * Incident Center APIs — behavior unchanged.
 */
const { readIncidents, writeIncidents, createIncidentId } = require('../services/incidents');

function registerIncidentRoutes(app, ctx) {
  const { requireAuth, audit, sendNotificationEvent } = ctx;

  app.get('/api/incidents', requireAuth, async (req, res) => {
    const items = await readIncidents();
    res.json({ incidents: items.sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || '')) });
  });

  app.post('/api/incidents', requireAuth, async (req, res) => {
    const title = String(req.body?.title || '').trim();
    const severity = ['low', 'medium', 'high', 'critical'].includes(req.body?.severity) ? req.body.severity : 'medium';
    if (!title) return res.status(400).json({ ok: false, error: 'Titolo richiesto' });
    const items = await readIncidents();
    const now = new Date().toISOString();
    const incident = {
      id: createIncidentId(),
      title,
      severity,
      status: 'open',
      source: req.body?.source || 'manual',
      owner: req.session?.user || 'admin',
      timeline: [{ ts: now, action: 'created', by: req.session?.user || 'admin', note: String(req.body?.note || '') }],
      createdAt: now,
      updatedAt: now,
    };
    items.push(incident);
    await writeIncidents(items);
    await audit('incident_created', { user: req.session?.user, incidentId: incident.id, severity });
    await sendNotificationEvent('incident_created', {
      channel: 'incidents',
      severity,
      note: title,
      actionHint: 'Apri Incident Center e valuta runbook',
    });
    res.json({ ok: true, incident });
  });

  app.post('/api/incidents/:id/status', requireAuth, async (req, res) => {
    const status = ['open', 'ack', 'resolved'].includes(req.body?.status) ? req.body.status : null;
    if (!status) return res.status(400).json({ ok: false, error: 'Status non valido' });
    const items = await readIncidents();
    const idx = items.findIndex((x) => x.id === req.params.id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'Incidente non trovato' });
    const now = new Date().toISOString();
    items[idx].status = status;
    items[idx].updatedAt = now;
    items[idx].timeline = Array.isArray(items[idx].timeline) ? items[idx].timeline : [];
    items[idx].timeline.push({ ts: now, action: status, by: req.session?.user || 'admin', note: String(req.body?.note || '') });
    await writeIncidents(items);
    await audit('incident_status_change', { user: req.session?.user, incidentId: req.params.id, status });
    await sendNotificationEvent('incident_status_change', {
      channel: 'incidents',
      severity: items[idx].severity || 'medium',
      note: `${items[idx].title} -> ${status}`,
    });
    res.json({ ok: true, incident: items[idx] });
  });
}

module.exports = { registerIncidentRoutes };
