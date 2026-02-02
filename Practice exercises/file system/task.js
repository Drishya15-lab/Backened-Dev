//file copy from input.txt to output.txt using pipe 
const fs = require('fs');

const readStream = fs.createReadStream('input.txt');
const writeStream = fs.createWriteStream('output1.txt');

readStream.pipe(writeStream);

