//file copy from input.txt to output.txt using pipe 
const fs = require('fs');

const readStream = fs.createReadStream('input.txt');
const writeStream = fs.createWriteStream('output.txt');

readStream.pipe(writeStream);

writeStream.on('finish', () => {
    console.log('File copy completed.');
});