
const fs = require('fs');

const data = fs.readFileSync('data.json', 'utf-8');


const obj = JSON.parse(data);


console.log("Parsed Object:", obj);
console.log("Name:", obj.name);
console.log("Role:", obj.role);
console.log("Skills:", obj.skills.join(", "));