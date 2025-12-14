const express = require('express');
const _ = require('lodash');  // Уязвимая зависимость
const serialize = require('serialize-javascript');  // Уязвимая для десериализации
const sqlite3 = require('sqlite3').verbose();  // БД для SQL injection
const bodyParser = require('body-parser');
const crypto = require('crypto');  // Для weak hashing (MD5)
const fs = require('fs');  // Для file operations
const path = require('path');

const app = express();
const port = 3000;

// Hard-coded credentials (SAST: security hotspot)
const adminPassword = 'admin123';  // Плохо: hard-coded пароль
const apiKey = 'super-secret-key-12345';  // Утечка секрета

// Настройка БД (in-memory для теста, но с SQL injection риском)
// const db = new sqlite3.Database(':memory:');
// db.serialize(() => {
//  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
//  db.run(`INSERT INTO users (username, password) VALUES ('admin', '${adminPassword}')`);
// });

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Логирование чувствительных данных (SAST: vulnerability - не логируйте пароли!)
app.use((req, res, next) => {
  if (req.body.password) {
    console.log(`Logged password: ${req.body.password}`);  // Плохо: утечка в логи
  }
  next();
});

// Endpoint с небезопасным eval (SAST: code injection)
app.post('/eval', (req, res) => {
  const userInput = req.body.input;
  try {
    const result = eval(userInput);  // Риск: выполнение произвольного кода
    res.send({ result });
  } catch (error) {
    res.status(500).send({ error: 'Execution failed' });
  }
});

// Endpoint с lodash merge (SCA: prototype pollution)
app.get('/merge', (req, res) => {
  const obj1 = { a: 1 };
  const obj2 = req.query.obj ? JSON.parse(req.query.obj) : {};  // Нет валидации
  const merged = _.merge(obj1, obj2);  // Уязвимость в старой lodash
  res.send(merged);
});

// Endpoint с утечкой секрета
app.get('/secret', (req, res) => {
  res.send({ key: apiKey });  // Прямой доступ к секрету
});

// Новый: SQL injection vulnerability (SAST: injection risk)
app.get('/user', (req, res) => {
  const username = req.query.username;
  // Плохо: прямое вставление user input в SQL без параметризации
  db.get(`SELECT * FROM users WHERE username = '${username}'`, (err, row) => {
    if (err) {
      res.status(500).send({ error: 'Database error' });
    } else {
      res.send(row || { message: 'User not found' });
    }
  });
});

// Новый: Weak password hashing (SAST: weak cryptography)
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');  // Плохо: MD5 устаревший и слабый
  db.run(`INSERT INTO users (username, password) VALUES ('${username}', '${hash}')`);  // Ещё и SQL injection здесь
  res.send({ message: 'User registered' });
});

// Новый: Insecure deserialization (SAST/SCA: RCE risk с уязвимой lib)
app.post('/deserialize', (req, res) => {
  const serializedData = req.body.data;
  try {
    const deserialized = eval(`(${serialize(serializedData, { unsafe: true })})`)  // Плохо: unsafe десериализация + eval
    res.send(deserialized);
  } catch (error) {
    res.status(500).send({ error: 'Deserialization failed' });
  }
});

// Новый: XSS vulnerability (SAST: cross-site scripting)
app.get('/echo', (req, res) => {
  const message = req.query.message;
  // Плохо: прямой вывод user input без escaping
  res.send(`<html><body><h1>${message}</h1></body></html>`);  // Пример: ?message=<script>alert('XSS')</script>
});

// Новый: Insecure file upload (SAST: path traversal, arbitrary file write)
app.post('/upload', (req, res) => {
  const fileContent = req.body.content;
  const fileName = req.body.filename;  // Нет валидации — риск path traversal (../../etc/passwd)
  fs.writeFileSync(path.join(__dirname, 'uploads', fileName), fileContent);  // Плохо: arbitrary write
  res.send({ message: 'File uploaded' });
});

app.listen(port, () => {
  console.log(`Vulnerable server running at http://localhost:${port}`);
});

// For new check 