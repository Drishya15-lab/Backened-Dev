const fs = require('fs');
const path = require('path');

class SimpleLogger {
  constructor(filename = 'my_log.txt') {
    this.filePath = path.resolve(filename);
  }

  log(message) {
    // Timestamp format: YYYY-MM-DD HH:MM:SS
    const timestamp = new Date().toISOString().replace('T', ' ').split('.')[0];
    const logEntry = `[${timestamp}] ${message}\n`;

    fs.appendFile(this.filePath, logEntry, (err) => {
      if (err) {
        console.error('Error writing to log file:', err);
      }
    });
  }
}

// Example usage
const logger = new SimpleLogger();

logger.log('Application started');
logger.log('Performing some task...');
logger.log('Application finished successfully');