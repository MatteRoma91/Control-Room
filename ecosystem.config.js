/**
 * PM2 - Control Room
 * Dashboard per gestione processi PM2
 */
module.exports = {
  apps: [
    {
      name: 'control-room',
      script: 'server.js',
      cwd: '/home/ubuntu/control-room',

      exec_mode: 'fork',
      instances: 1,

      autorestart: true,
      watch: false,
      max_memory_restart: '200M',

      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      out_file: '/home/ubuntu/.pm2/logs/control-room-out.log',
      error_file: '/home/ubuntu/.pm2/logs/control-room-error.log',

      env: {
        NODE_ENV: 'production',
        PORT: 3005,
      },
    },
  ],
};
