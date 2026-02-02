const express = require('express');
const app = express();
app.use(express.json());

let tasks = [];
let id = 1;

app.post('/tasks', (req, res) => {
  const task = { id: id++, ...req.body };
  tasks.push(task);
  res.json(task);
});

app.get('/tasks', (req, res) => {
  res.json(tasks);
});

app.put('/tasks/:id', (req, res) => {
  const task = tasks.find(t => t.id == req.params.id);
  if (task) {
    Object.assign(task, req.body);
    res.json(task);
  } else res.sendStatus(404);
});

app.delete('/tasks/:id', (req, res) => {
  tasks = tasks.filter(t => t.id != req.params.id);
  res.sendStatus(204);
});

app.listen(3000);