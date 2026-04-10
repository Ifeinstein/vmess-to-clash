module.exports = {
  apps: [
    {
      name: "vmess-to-clash",
      script: "app.py",
      interpreter: "python",
      cwd: __dirname,
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "300M",
      env: {
        HOST: "0.0.0.0",
        PORT: "8000",
      },
      error_file: "data/logs/pm2-error.log",
      out_file: "data/logs/pm2-out.log",
      time: true,
    },
  ],
};
