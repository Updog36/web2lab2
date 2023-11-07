"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = __importDefault(require("express"));
var path_1 = __importDefault(require("path"));
var dotenv = __importStar(require("dotenv"));
var crypto_1 = __importDefault(require("crypto"));
dotenv.config();
var sanitizer = require('sanitizer');
var app = (0, express_1.default)();
app.set("views", path_1.default.join(__dirname, "views"));
app.set('view engine', 'pug');
var Pool = require('pg').Pool;
var pool = new Pool({
    /*
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    */
    user: 'postgres',
    host: 'localhost',
    database: 'web2lab2',
    password: 'bazepodataka',
    port: 5432 //,
    //ssl: true
});
var port = 4080;
app.use(express_1.default.urlencoded({ extended: true }));
app.use(express_1.default.static(__dirname + '/stylesheets'));
app.get('/', function (req, res) {
    res.render('index');
});
// simulate XSS script attack using the database
app.get('/xss', function (req, res) {
    pool.query('SELECT * FROM comments ORDER BY id ASC', function (err, result) {
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        console.log(result.rows);
        res.render('xss', { comments: result.rows });
    });
});
app.post('/xss', function (req, res) {
    var comment = req.body.comment;
    var vulnerable = req.body.vulnerable;
    if (vulnerable) {
        pool.query('INSERT INTO comments (comment) VALUES ($1)', [comment], function (err, result) {
            if (err) {
                return console.error('Error executing query', err.stack);
            }
            res.redirect('/xss');
        });
    }
    else {
        // prevent xss
        var sanitizedComment = sanitizer.sanitize(comment);
        console.log(sanitizedComment);
        pool.query('INSERT INTO comments (comment) VALUES ($1)', [sanitizedComment], function (err, result) {
            if (err) {
                return console.error('Error executing query', err.stack);
            }
            res.redirect('/xss');
        });
    }
});
app.get('/xss/reset', function (req, res) {
    pool.query('DELETE FROM comments', function (err, result) {
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        res.redirect('/xss');
    });
});
app.get('/sde', function (req, res) {
    // simulate sensitive data exposure attack
    pool.query('SELECT * FROM users ORDER BY id ASC', function (err, result) {
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        res.render('sde', { users: result.rows });
    });
});
app.post('/sde', function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
    var vulnerable = req.body.vulnerable;
    if (username == '' || password == '') {
        res.redirect('/sde');
    }
    if (vulnerable) {
        pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, password], function (err, result) {
            if (err) {
                return console.error('Error executing query', err.stack);
            }
            res.redirect('/sde');
        });
    }
    else {
        pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, crypto_1.default.createHash('sha256').update(password).digest('hex')], function (err, result) {
            if (err) {
                return console.error('Error executing query', err.stack);
            }
            res.redirect('/sde');
        });
    }
});
app.get('/sde/reset', function (req, res) {
    pool.query('DELETE FROM users', function (err, result) {
        if (err) {
            return console.error('Error executing query', err.stack);
        }
        res.redirect('/sde');
    });
});
app.listen(port, function () {
    console.log("Lab2 app listening at port ".concat(port));
});
