 // Import the built-in 'fs' module
//const fs = require('fs');

// Create a readable stream
//const readStream = fs.createReadStream('example.txt', {
//    encoding: 'utf8',
    //highWaterMark: 64 * 1024   // buffer size = 64KB
//});

// Event when data chunk is received
//readStream.on("data", (chunk) => {
   // console.log("chunk received:", chunk.length);
//});

// Event when no more data is left
//readStream.on("end", () => {
  //  console.log("no more data");
//});
//const writeStream = fs.createWriteStream('output.txt');
//writeStream.write('Hello, World!\n');
//writeStream.write('This is a writable stream example.\n');
//writeStream.end('Stream ended.\n');

//writeStream.on('finish', () => {
  //  console.log('All data written to file.');
//});
//Transform stream example
// Import the built-in 'fs' module
const fs = require('fs');
const { Transform } = require('stream');

// Transform stream to convert text to uppercase
const upperCaseTransform = new Transform({
    transform(chunk, encoding, callback) {
        // Convert chunk to uppercase and push forward
        this.push(chunk.toString().toUpperCase());
        callback();
    }
});

// Pipe flow: read -> transform -> write
fs.createReadStream('example.txt', { encoding: 'utf8' })
    .pipe(upperCaseTransform)
    .pipe(fs.createWriteStream('output_uppercase.txt'))
    .on('finish', () => {
        console.log('Transformation complete. Check output_uppercase.txt');
    });