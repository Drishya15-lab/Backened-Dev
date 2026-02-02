const fs = require('fs');

const inputFile = 'input.txt';
const outputFile = 'wordCount.txt';

fs.readFile(inputFile, 'utf8', (err, data) => {
  if (err) {
    console.error(err);
    return;
  }

  const words = data.trim().split(/\s+/);
  const wordCount = words.length;

  fs.writeFile(outputFile, `Word count: ${wordCount}`, (err) => {
    if (err) {
      console.error(err);
      return;
    }
    console.log(`Word count written to ${outputFile}`);
  });
});