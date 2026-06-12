const http = require('http');

const server = http.createServer((req, res) => {
    const roll = Math.floor(Math.random() * 6) + 1; // Simulate rolling a six-sided die
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`
        <h1>Dice Roller</h1>
        <p>You rolled a: ${roll}</p>
        <button onclick="window.location.reload()">Roll again</button>
    `);
});

server.listen(3000, () => {
    console.log('Dice roller app is running on port 3000');
});