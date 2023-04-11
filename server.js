const express = require('express');
const mysql2 = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const jwt_secret_key = 'jwt'

app.use(bodyParser.json());

const connection = mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'todo_app'
});

connection.connect((error) => {
    if (error) console.error(error);
});

app.post('/register', async (req, res) => {

    const { name, surname, email, password } = req.body;

    const existingUser = connection.query('SELECT * FROM users WHERE email = ?', [email]);

    if (!existingUser.length === 0) {
        return res.status(400).send({ error: 'User with given email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = connection.query('INSERT INTO users (name, surname, email, password) VALUES (?, ?, ?, ?)', [name, surname, email, hashedPassword], (err) => {
        if (err) console.error(err);
    });
    connection.commit();
    const userId = result.insertId;

    const token = jwt.sign({ id: userId, email }, jwt_secret_key);
    res.send({ token });
}
);

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    let rows = [];
    connection.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
        if (error) console.error(error);

        rows = results;

        if (rows.length === 0) {
            return res.status(401).send({ error: 'Invalid email or password' });
        }

        const user = rows[0];

        const passwordMatches = bcrypt.compare(password, user.password);
        if (!passwordMatches) {
            return res.status(401).send({ error: 'Invalid email or password' });
        }

        const token = jwt.sign({ id: user.id, email }, jwt_secret_key);
        res.send({ token });
    });
});

const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send({ error: 'Missing authorization header' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, jwt_secret_key);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).send({ error: 'Invalid token' });
    }
};

app.get('/events', authenticate, async (req, res) => {
    const { datetimeFrom, datetimeTo, durationFrom, durationTo } = req.body;

    let whereClause = '';
    let queryParams = [];
    if (datetimeFrom) {
        whereClause += 'datetime >= \'?\' AND ';
        queryParams.push(datetimeFrom);
    }
    if (datetimeTo) {
        whereClause += 'datetime <= \'?\' AND ';
        queryParams.push(datetimeTo);
    }
    if (durationFrom) {
        whereClause += 'duration >= ? AND ';
        queryParams.push(durationFrom);
    }
    if (durationTo) {
        whereClause += 'duration <= ? AND ';
        queryParams.push(durationTo);
    }
    if (whereClause) {
        whereClause = 'WHERE ' + whereClause.slice(0, -5);
    }

    let query = 'SELECT * FROM events ';
    const whereClauseParts = whereClause.split('?');
    for (let i = 0; i < queryParams.length; i++) {
        query += whereClauseParts[i];
        query += queryParams[i];
    }
    connection.query(query, (err, events) => {
        if (err) console.error(err);
        res.send(events);
    });
});

app.post('/events', authenticate, async (req, res) => {
    const { datetime, title, description, duration } = req.body;

    connection.query('INSERT INTO events (datetime, title, description, duration) VALUES (?, ?, ?, ?)', [datetime, title, description, duration], (err, result) => {
        if (err) console.error(err);
        const eventId = result.insertId;

        connection.query('SELECT * FROM events WHERE id = ?', [eventId], (err, result) => {
            if (err) console.error(err);
            res.send(result[0]);
        });
    });

    connection.commit();
});

app.put('/events/:id', authenticate, async (req, res) => {
    const eventId = req.params.id;
    const { datetime, title, description, duration } = req.body;

    connection.query('UPDATE events SET datetime = ?, title = ?, description = ?, duration = ? WHERE id = ?', [datetime, title, description, duration, eventId]);
    connection.commit();

    connection.query('SELECT * FROM events WHERE id = ?', [eventId], (err, event) => {
        if (err) console.error(err);
        res.send(event[0]);
    });
});

app.delete('/events/:id', authenticate, async (req, res) => {
    const eventId = req.params.id;

    connection.query('DELETE FROM events WHERE id = ?', [eventId], (err) => {
        if (err) console.error(err);
    });
    connection.commit();

    res.send({ message: `Event with id = ${eventId} deleted successfully` });
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});


