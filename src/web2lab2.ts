import express from 'express';
import path from 'path'
import * as dotenv from 'dotenv';
import crypto from 'crypto';
dotenv.config()

var sanitizer = require('sanitizer');
const app = express();
app.set("views", path.join(__dirname, "views"));
app.set('view engine', 'pug');
const { Pool } = require('pg');
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: 5432
});

const port = 4080;
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/stylesheets'));

app.get('/',  function (req, res) {
  res.render('index');
});

// simulate XSS script attack using the database
app.get('/xss',  function (req, res) {
  pool.query('SELECT * FROM comments ORDER BY id ASC', (err: any, result: any) => {
    if (err) {
      return console.error('Error executing query', err.stack)
    }
    console.log(result.rows);
    res.render('xss', { comments: result.rows });
  });
}
);

app.post('/xss',  function (req, res) {
  const comment = req.body.comment;
  const vulnerable = req.body.vulnerable;
  if (vulnerable) {
    pool.query('INSERT INTO comments (comment) VALUES ($1)', [comment], (err: any, result: any) => {
      if (err) {
        return console.error('Error executing query', err.stack)
      }
      res.redirect('/xss');
    });
  } else {
    // prevent xss
    const sanitizedComment = sanitizer.sanitize(comment);
    console.log(sanitizedComment);
    pool.query('INSERT INTO comments (comment) VALUES ($1)', [sanitizedComment], (err: any, result: any) => {
      if (err) {
        return console.error('Error executing query', err.stack)
      }
      res.redirect('/xss');
    });
  }
}
);

app.get('/xss/reset',  function (req, res) {
  pool.query('DELETE FROM comments', (err: any, result: any) => {
    if (err) {
      return console.error('Error executing query', err.stack)
    }
    res.redirect('/xss');
  });
}
);

app.get('/sde',  function (req, res) {
  // simulate sensitive data exposure attack
  pool.query('SELECT * FROM users ORDER BY id ASC', (err: any, result: any) => {
    if (err) {
      return console.error('Error executing query', err.stack)
    }
    res.render('sde', { users: result.rows });
  });
}
);

app.post('/sde',  function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const vulnerable = req.body.vulnerable;
  if (username == '' || password == '') {
    res.redirect('/sde');
  }

  if (vulnerable) {
    pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, password], (err: any, result: any) => {
      if (err) {
        return console.error('Error executing query', err.stack)
      }
      res.redirect('/sde');
    });
  }
  else {
    pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, crypto.createHash('sha256').update(password).digest('hex')], (err: any, result: any) => {
      if (err) {
        return console.error('Error executing query', err.stack)
      }
      res.redirect('/sde');
    });
  }
}
);

app.get('/sde/reset',  function (req, res) {
  pool.query('DELETE FROM users', (err: any, result: any) => {
    if (err) {
      return console.error('Error executing query', err.stack)
    }
    res.redirect('/sde');
  });
}
);




app.listen(port, () => {
  console.log(`Lab2 app listening at port ${port}`)
 })
