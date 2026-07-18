const path = require('path');

const ALLOWED_CWD_PREFIX = '/home/ubuntu/';

function isPathAllowed(filePath) {
  const resolved = path.resolve(filePath);
  return resolved.startsWith(ALLOWED_CWD_PREFIX);
}

module.exports = { ALLOWED_CWD_PREFIX, isPathAllowed };
