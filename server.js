const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_jwt_key_dormitory';

// เชื่อมต่อฐานข้อมูล MySQL
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'dormitory_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware ตรวจสอบ JWT Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'กรุณาเข้าสู่ระบบก่อนใช้งาน' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Session หมดอายุ กรุณาล็อกอินใหม่' });
        req.user = user;
        next();
    });
};

// 1. Auth API
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length === 0) return res.status(401).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });

        const token = jwt.sign(
            { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ success: true, token, user: { id: user.user_id, username: user.username, role: user.role, full_name: user.full_name } });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 2. Room API
app.get('/api/rooms', authenticateToken, async (req, res) => {
    try {
        const [rooms] = await pool.execute(`
            SELECT 
                r.room_id, 
                r.room_number, 
                r.monthly_rent, 
                r.status, 
                c.contract_id,
                COALESCE(t.full_name, 'ไม่มีผู้เช่า') AS tenant_name
            FROM rooms r
            LEFT JOIN contracts c ON r.room_id = c.room_id AND c.contract_status = 'active'
            LEFT JOIN tenants t ON c.tenant_id = t.tenant_id
            ORDER BY r.room_number ASC
        `);
        res.json(rooms);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/rooms/:id/status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    try {
        await pool.execute('UPDATE rooms SET status = ? WHERE room_id = ?', [status, req.params.id]);
        res.json({ success: true, message: 'อัปเดตสถานะห้องสำเร็จ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 3. Bill API
app.get('/api/bills', authenticateToken, async (req, res) => {
    try {
        const [bills] = await pool.execute(`
            SELECT 
                b.bill_id, 
                b.month_year, 
                b.total_amount, 
                b.payment_status, 
                r.room_number, 
                COALESCE(t.full_name, '-') AS tenant_name
            FROM bills b
            JOIN contracts c ON b.contract_id = c.contract_id
            JOIN rooms r ON c.room_id = r.room_id
            JOIN tenants t ON c.tenant_id = t.tenant_id
            ORDER BY b.bill_id DESC
        `);
        res.json(bills);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/bills', authenticateToken, async (req, res) => {
    const { contract_id, month_year, water_unit, water_price, electricity_unit, electricity_price, room_rent } = req.body;
    const total_amount = parseFloat(room_rent || 0) + parseFloat(water_price || 0) + parseFloat(electricity_price || 0);

    try {
        await pool.execute(
            `INSERT INTO bills (contract_id, month_year, water_unit, water_price, electricity_unit, electricity_price, total_amount, payment_status)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [contract_id, month_year, water_unit, water_price, electricity_unit, electricity_price, total_amount]
        );
        res.json({ success: true, message: 'สร้างบิลเรียบร้อยแล้ว' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/bills/:id/pay', authenticateToken, async (req, res) => {
    try {
        await pool.execute('UPDATE bills SET payment_status = "paid" WHERE bill_id = ?', [req.params.id]);
        res.json({ success: true, message: 'บันทึกการชำระเงินเรียบร้อยแล้ว' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// 4. Maintenance API
app.get('/api/maintenance', authenticateToken, async (req, res) => {
    try {
        const [list] = await pool.execute(`
            SELECT 
                m.request_id, 
                m.title, 
                m.description, 
                m.status, 
                r.room_number, 
                COALESCE(t.full_name, 'ผู้ดูแลระบบ') AS tenant_name
            FROM maintenance_requests m
            JOIN rooms r ON m.room_id = r.room_id
            LEFT JOIN tenants t ON m.tenant_id = t.tenant_id
            ORDER BY m.request_id DESC
        `);
        res.json(list);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/maintenance', authenticateToken, async (req, res) => {
    const { room_id, title, description } = req.body;
    try {
        await pool.execute(
            'INSERT INTO maintenance_requests (room_id, title, description, status) VALUES (?, ?, ?, "pending")',
            [room_id, title, description]
        );
        res.json({ success: true, message: 'บันทึกรายการแจ้งซ่อมสำเร็จ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/maintenance/:id/status', authenticateToken, async (req, res) => {
    const { status } = req.body;
    try {
        await pool.execute('UPDATE maintenance_requests SET status = ? WHERE request_id = ?', [status, req.params.id]);
        res.json({ success: true, message: 'อัปเดตสถานะการแจ้งซ่อมเรียบร้อย' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});