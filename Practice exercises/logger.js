const fs = require('fs');
const os = require('os');

setInterval(() => {
  const info = `CPU: ${os.cpus().length}, Memory: ${os.totalmem()}, Platform: ${os.platform()}\n`;
  fs.appendFile('system.log', info, err => {
    if (err) console.error(err);
  });
}, 5000);