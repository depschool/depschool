const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'my-secret-key';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const db = new sqlite3.Database('./database.sqlite');

// Создаём таблицы
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE,
    password TEXT,
    fullname TEXT,
    role TEXT,
    userStatus TEXT
  )`);
  
  // Добавляем админа если нет
  db.get(`SELECT * FROM users WHERE login = 'admin'`, (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run(`INSERT INTO users (login, password, fullname, role, userStatus) VALUES (?, ?, ?, ?, ?)`,
        ['admin', hash, 'Администратор', 'admin', 'active']);
    }
  });
});

// Вход
app.post('/api/login', (req, res) => {
  const { login, password } = req.body;
  db.get(`SELECT * FROM users WHERE login = ?`, [login], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY);
    res.json({ token, user: { id: user.id, login: user.login, fullname: user.fullname, role: user.role } });
  });
});

// Проверка токена
function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Нет токена' });
  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Неверный токен' });
  }
}

// Получить пользователей
app.get('/api/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещён' });
  db.all(`SELECT id, login, fullname, role, userStatus FROM users`, (err, users) => {
    res.json(users);
  });
});

app.listen(PORT, () => {
  console.log(`Сервер на http://localhost:${PORT}`);
});