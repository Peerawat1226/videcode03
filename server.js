require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_key';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'))); // วางบรรทัดนี้ไว้เหมือนบรรทัดที่ 17

// Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '', 
    database: process.env.DB_NAME || 'dormitory_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware สำหรับตรวจสอบ JWT Token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // รูปแบบ "Bearer <token>"

    if (!token) {
        return res.status(401).json({ success: false, message: 'กรุณาเข้าสู่ระบบก่อนใช้งาน' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
        }
        req.user = user;
        next();
    });
};

// ==========================================
// 🔑 AUTHENTICATION ROUTES (ระบบล็อกอิน)
// ==========================================

// 1. API เข้าสู่ระบบ (Login)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'กรุณากรอก Username และ Password' });
    }

    try {
        const [users] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
        }

        // สร้าง JWT Token (มีอายุ 1 วัน)
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username, role: user.role, full_name: user.full_name },
            JWT_SECRET,
            { expiresIn: '1d' }
        );

        res.json({
            success: true,
            message: 'เข้าสู่ระบบสำเร็จ',
            token: token,
            user: {
                id: user.user_id,
                username: user.username,
                full_name: user.full_name,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
    }
});

// 2. API ตรวจสอบข้อมูลผู้ใช้ปัจจุบัน (Check Auth)
app.get('/api/auth/me', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// ==========================================
// 🏢 PROTECTED DORMITORY ROUTES (ต้อง Login ก่อน)
// ==========================================

// ดึงข้อมูลห้องพักทั้งหมด
app.get('/api/rooms', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                r.room_id,
                r.room_id AS id,
                r.room_number,
                r.room_number AS room_name,
                r.room_number AS number,
                r.room_number AS name,
                r.monthly_rent,
                r.status,
                active_contract.contract_id,
                COALESCE(t.full_name, 'ไม่มีผู้เช่า') AS tenant_name,
                COALESCE(t.full_name, 'ไม่มีผู้เช่า') AS tenant
            FROM rooms r
            LEFT JOIN (
                SELECT room_id, contract_id, tenant_id
                FROM contracts 
                WHERE contract_status = 'active'
                GROUP BY room_id
            ) active_contract ON r.room_id = active_contract.room_id
            LEFT JOIN tenants t ON active_contract.tenant_id = t.tenant_id
            ORDER BY r.room_id ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error('API Rooms Error:', err);
        res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงข้อมูลห้องพัก' });
    }
});

// อัปเดตสถานะห้องพัก
app.put('/api/rooms/:id/status', authenticateToken, async (req, res) => {
    const roomId = req.params.id;
    const { status } = req.body;

    try {
        await pool.execute('UPDATE rooms SET status = ? WHERE room_id = ?', [status, roomId]);
        res.json({ success: true, message: 'อัปเดตสถานะห้องพักสำเร็จ' });
    } catch (err) {
        console.error('API Update Room Status Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ดึงรายการบิลค่าเช่า
app.get('/api/bills', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                b.*,
                b.bill_id AS id,
                b.month_year AS billing_month,
                b.month_year AS month,
                r.room_number,
                r.room_number AS room_name,
                COALESCE(t.full_name, 'ไม่ระบุผู้เช่า') AS tenant_name,
                COALESCE(t.full_name, 'ไม่ระบุผู้เช่า') AS tenant
            FROM bills b
            LEFT JOIN contracts c ON b.contract_id = c.contract_id
            LEFT JOIN rooms r ON c.room_id = r.room_id
            LEFT JOIN tenants t ON c.tenant_id = t.tenant_id
            ORDER BY b.bill_id DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error('API Bills Error:', err);
        res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงรายการบิล' });
    }
});

// ออกบิลใหม่
app.post('/api/bills', authenticateToken, async (req, res) => {
    let { contract_id, month_year, water_unit, water_price, electricity_unit, electricity_price, room_rent } = req.body;

    try {
        let [contracts] = await pool.execute(
            'SELECT c.contract_id, r.monthly_rent FROM contracts c JOIN rooms r ON c.room_id = r.room_id WHERE c.contract_id = ?', 
            [contract_id]
        );

        if (contracts.length === 0) {
            [contracts] = await pool.execute(
                'SELECT contract_id, r.monthly_rent FROM contracts c JOIN rooms r ON c.room_id = r.room_id WHERE c.contract_status = "active" ORDER BY c.contract_id DESC LIMIT 1'
            );
            if (contracts.length > 0) {
                contract_id = contracts[0].contract_id;
            } else {
                return res.status(400).json({ success: false, message: 'ไม่พบสัญญาเช่าที่ใช้งานอยู่' });
            }
        }

        const rent = parseFloat(room_rent) || parseFloat(contracts[0]?.monthly_rent) || 0;
        const wPrice = parseFloat(water_price) || 0;
        const ePrice = parseFloat(electricity_price) || 0;
        const total_amount = rent + wPrice + ePrice;

        const sql = `
            INSERT INTO bills 
            (contract_id, month_year, water_unit, water_price, electricity_unit, electricity_price, total_amount, payment_status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            ON DUPLICATE KEY UPDATE
            water_unit = VALUES(water_unit),
            water_price = VALUES(water_price),
            electricity_unit = VALUES(electricity_unit),
            electricity_price = VALUES(electricity_price),
            total_amount = VALUES(total_amount)
        `;
        const [result] = await pool.execute(sql, [
            contract_id, month_year, water_unit || 0, wPrice, electricity_unit || 0, ePrice, total_amount
        ]);

        res.json({ success: true, bill_id: result.insertId || result.updateId, message: 'บันทึกข้อมูลบิลเรียบร้อยแล้ว' });
    } catch (err) {
        console.error('API Post Bill Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// อัปเดตการชำระเงิน
app.put('/api/bills/:id/pay', authenticateToken, async (req, res) => {
    try {
        await pool.execute("UPDATE bills SET payment_status = 'paid' WHERE bill_id = ?", [req.params.id]);
        res.json({ success: true, message: 'บันทึกการชำระเงินสำเร็จ' });
    } catch (err) {
        console.error('API Pay Bill Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// ดึงรายการแจ้งซ่อม
app.get('/api/maintenance', authenticateToken, async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                m.*,
                r.room_number,
                r.room_number AS room_name,
                COALESCE(t.full_name, 'ผู้ดูแลระบบ') AS tenant_name
            FROM maintenance_requests m
            LEFT JOIN rooms r ON m.room_id = r.room_id
            LEFT JOIN tenants t ON m.tenant_id = t.tenant_id
            ORDER BY m.request_id DESC
        `);
        res.json(rows);
    } catch (err) {
        console.error('API Maintenance Get Error:', err);
        res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงรายการแจ้งซ่อม' });
    }
});

// สร้างรายการแจ้งซ่อมใหม่
app.post('/api/maintenance', authenticateToken, async (req, res) => {
    const { room_id, title, description, status } = req.body;

    try {
        const [contracts] = await pool.execute(
            'SELECT tenant_id FROM contracts WHERE room_id = ? AND contract_status = "active" LIMIT 1',
            [room_id]
        );
        const tenant_id = contracts.length > 0 ? contracts[0].tenant_id : null;

        const sql = `
            INSERT INTO maintenance_requests 
            (room_id, tenant_id, title, description, status) 
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await pool.execute(sql, [
            room_id, tenant_id, title, description || '', status || 'pending'
        ]);

        res.json({ success: true, request_id: result.insertId });
    } catch (err) {
        console.error('API Maintenance Post Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

// อัปเดตสถานะการแจ้งซ่อม
app.put('/api/maintenance/:id/status', authenticateToken, async (req, res) => {
    const requestId = req.params.id;
    const { status } = req.body;

    try {
        await pool.execute('UPDATE maintenance_requests SET status = ? WHERE request_id = ?', [status, requestId]);
        res.json({ success: true, message: 'อัปเดตสถานะการซ่อมสำเร็จ' });
    } catch (err) {
        console.error('API Update Maintenance Status Error:', err);
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/auth/register', async (req, res) => {
    const { username, password, full_name } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (username, password, full_name, role) VALUES (?, ?, ?, "admin") ON DUPLICATE KEY UPDATE password = VALUES(password)',
            [username, hashedPassword, full_name || 'ผู้ดูแลระบบ']
        );
        res.json({ success: true, message: 'สร้างบัญชีเรียบร้อยแล้ว' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// สั่งเปิดโฟลเดอร์ public โดยตรง
app.use(express.static('public'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// รันเซิร์ฟเวอร์
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));