require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const mysql = require('mysql2/promise')

const app = express()
const port = 3000

app.use(express.json())

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    if (!authHeader) return res.status(401).json({ error: 'Token saknas' })

    const token = authHeader.split(' ')[1]
    if (!token) return res.status(401).json({ error: 'Token saknas' })

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Ogiltigt token' })
        req.user = user
        next()
    })
}

app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="sv">
            <head><meta charset="UTF-8"><title>API Dokumentation</title></head>
            <body>
                <h1>REST API Dokumentation</h1>
                <ul>
                    <li><strong>POST</strong> /register - Skapa ett användarkonto</li>
                    <li><strong>POST</strong> /login - Logga in och få en JWT-token</li>
                    <li><strong>GET</strong> /products - Hämta alla produkter (kräver JWT)</li>
                    <li><strong>GET</strong> /products/:id - Hämta en specifik produkt (kräver JWT)</li>
                    <li><strong>POST</strong> /products - Skapa en ny produkt (kräver JWT)</li>
                    <li><strong>PUT</strong> /products/:id - Uppdatera en produkt (kräver JWT)</li>
                    <li><strong>DELETE</strong> /produkter/:id - Ta bort en produkt (kräver JWT)</li>
                </ul>
            </body>
        </html>
    `)
})

app.post('/register', async (req, res) => {
    const { username, password, email } = req.body
    if (!username || !password || !email) return res.status(400).json({ error: 'Användarnamn, lösenord och email krävs' })

    try {
        const hashedPassword = await bcrypt.hash(password, 10)
        const [result] = await pool.query(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email]
        )
        res.status(201).json({ id: result.insertId, username, email })
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Användarnamnet finns redan' })
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.post('/login', async (req, res) => {
    const { username, password } = req.body
    if (!username || !password) return res.status(400).json({ error: 'Användarnamn och lösenord krävs' })

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username])
        const user = rows[0]
        if (!user) return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord' })

        const validPass = await bcrypt.compare(password, user.password)
        if (!validPass) return res.status(401).json({ error: 'Felaktigt användarnamn eller lösenord' })

        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN })
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.get('/products', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, price FROM products')
        res.json(rows)
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.get('/products/:id', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, price FROM products WHERE id = ?', [req.params.id])
        if (rows.length === 0) return res.status(404).json({ error: 'Produkten hittades inte' })
        res.json(rows[0])
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.post('/products', authenticateToken, async (req, res) => {
    const { name, price } = req.body
    if (!name || price == null) return res.status(400).json({ error: 'Namn och pris krävs' })

    try {
        const [result] = await pool.query('INSERT INTO products (name, price) VALUES (?, ?)', [name, price])
        res.status(201).json({ id: result.insertId, name, price })
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.put('/products/:id', authenticateToken, async (req, res) => {
    const { name, price } = req.body
    if (!name && price == null) return res.status(400).json({ error: 'Minst ett fält krävs' })

    try {
        let query = 'UPDATE products SET '
        const params = []

        if (name) {
            query += 'name = ?, '
            params.push(name)
        }
        if (price != null) {
            query += 'price = ?, '
            params.push(price)
        }

        query = query.slice(0, -2) + ' WHERE id = ?'
        params.push(req.params.id)

        const [result] = await pool.query(query, params)
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Produkten hittades inte' })

        const [rows] = await pool.query('SELECT id, name, price FROM products WHERE id = ?', [req.params.id])
        res.json(rows[0])
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})

app.delete('/products/:id', authenticateToken, async (req, res) => {
    try {
        const [result] = await pool.query('DELETE FROM products WHERE id = ?', [req.params.id])
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Produkten hittades inte' })
        res.json({ message: 'Produkten har tagits bort' })
    } catch (err) {
        res.status(500).json({ error: 'Serverfel' })
    }
})


app.listen(port, () => {
    console.log(`Servern körs på http://localhost:${port}`)
})
