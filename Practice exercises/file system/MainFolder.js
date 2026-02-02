const fs = require('fs');

// Subfolder 1 + file
fs.mkdirSync('MainFolder/Sub1', { recursive: true });
fs.writeFileSync('MainFolder/Sub1/file1.txt', 'Hello from Sub1');

// Subfolder 2 + file
fs.mkdirSync('MainFolder/Sub2', { recursive: true });
fs.writeFileSync('MainFolder/Sub2/file2.txt', 'Hello from Sub2');

console.log("Folders and files created successfully!");
//fs.rmdirSync('MainFolder', { recursive: true });