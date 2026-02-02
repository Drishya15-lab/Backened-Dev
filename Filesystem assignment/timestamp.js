const fs = require('fs');
const path = require('path');


function getTimestamp() {
  const now = new Date();
  const yyyy = now.getFullYear();
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  const hh = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}_${hh}${min}${ss}`;
}


function backupFile(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error("File does not exist:", filePath);
    return;
  }

  const dir = path.dirname(filePath);
  const ext = path.extname(filePath);
  const base = path.basename(filePath, ext);

  const timestamp = getTimestamp();
  const backupName = `${base}_${timestamp}${ext}`;
  const backupPath = path.join(dir, backupName);

  fs.copyFileSync(filePath, backupPath);
  console.log(`Backup created: ${backupPath}`);
}

backupFile('example.txt');