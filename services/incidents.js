/**
 * Incident store helpers — behavior unchanged.
 */
const path = require('path');
const fs = require('fs').promises;
const { INCIDENTS_PATH } = require('../lib/constants');

async function readJsonFileSafe(filePath, fallbackValue) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (_) {
    return fallbackValue;
  }
}

async function appendLine(filePath, obj) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.appendFile(filePath, JSON.stringify(obj) + '\n', 'utf8');
}

async function readIncidents() {
  return readJsonFileSafe(INCIDENTS_PATH, []);
}

async function writeIncidents(items) {
  await fs.mkdir(path.dirname(INCIDENTS_PATH), { recursive: true });
  await fs.writeFile(INCIDENTS_PATH, JSON.stringify(items, null, 2), 'utf8');
}

function createIncidentId() {
  return `inc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

module.exports = {
  readJsonFileSafe,
  appendLine,
  readIncidents,
  writeIncidents,
  createIncidentId,
};
