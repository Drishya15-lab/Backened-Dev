const http = require('http');

const server = http.createServer((req, res) => {
    if (req.url === "/home") {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello World from my server!');
    } else if (req.url === "/about") {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('This is the About Page of my server.');
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Page Not Found');
    }
});

server.listen(8001, () => {
    console.log('Server is RUNNING at http://localhost:8001/');
});