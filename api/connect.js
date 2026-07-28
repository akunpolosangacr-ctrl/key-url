import { neon } from '@neondatabase/serverless';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const dbUrl = process.env.STORAGE_URL || process.env.DATABASE_URL;

    if (!dbUrl) {
        return res.status(500).json({
            status: false,
            message: "Database URL tidak ditemukan! Pastikan Integration Neon sudah terhubung."
        });
    }

    const sql = neon(dbUrl);

    try {
        // Otomatis pastikan tabel ada
        await sql`
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                label VARCHAR(255) NOT NULL,
                key_value VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expired_at TIMESTAMP NOT NULL,
                active_days INT NOT NULL
            );
        `;

        // 🔒 JIKA DIBUKA DI BROWSER DENGAN METODE GET (TANPA QUERY ACTION)
        if (req.method === 'GET' && !req.query.action) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.status(200).send(`
                <!DOCTYPE html>
                <html lang="id">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>API Endpoint Protected</title>
                    <style>
                        body {
                            background-color: #0f172a;
                            color: #f8fafc;
                            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                            padding: 20px;
                            box-sizing: border-color;
                        }
                        .card {
                            background-color: #1e293b;
                            border: 1px solid #334155;
                            border-radius: 16px;
                            padding: 40px 30px;
                            text-align: center;
                            max-width: 420px;
                            width: 100%;
                            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
                        }
                        .icon-container {
                            width: 80px;
                            height: 80px;
                            background: rgba(239, 68, 68, 0.1);
                            border: 1px solid #ef4444;
                            border-radius: 50%;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            margin: 0 auto 20px auto;
                            color: #ef4444;
                        }
                        h1 { font-size: 1.4rem; color: #ef4444; margin-bottom: 10px; font-weight: 700; letter-spacing: 1px; }
                        p { font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 20px; }
                        .badge {
                            background: #0f172a;
                            border: 1px solid #334155;
                            color: #38bdf8;
                            padding: 8px 14px;
                            border-radius: 8px;
                            font-family: monospace;
                            font-size: 0.85rem;
                            display: inline-block;
                        }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="icon-container">
                            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                            </svg>
                        </div>
                        <h1>PROTECTED ENDPOINT</h1>
                        <p>Akses via Browser (GET) ditolak. Endpoint ini khusus digunakan untuk validasi API Key menggunakan metode <strong>POST</strong> dari HTTP Injector / Aplikasi Client.</p>
                        <div class="badge">METHOD REQUIRED: POST</div>
                    </div>
                </body>
                </html>
            `);
        }

        const action = req.query.action || req.body?.action;

        // --- ACTION: CREATE KEY ---
        if (action === 'create') {
            const { label, days } = req.body || {};
            const activeDays = parseInt(days) || 30;
            const keyLabel = label || 'Untitled Key';

            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let keyValue = 'vdb_';
            for (let i = 0; i < 32; i++) {
                keyValue += chars.charAt(Math.floor(Math.random() * chars.length));
            }

            const expiredAt = new Date(Date.now() + activeDays * 24 * 60 * 60 * 1000);

            const result = await sql`
                INSERT INTO api_keys (label, key_value, expired_at, active_days)
                VALUES (${keyLabel}, ${keyValue}, ${expiredAt.toISOString()}, ${activeDays})
                RETURNING *;
            `;

            return res.status(200).json({ status: true, message: "API Key tersimpan!", data: result[0] });
        }

        // --- ACTION: DELETE KEY ---
        if (action === 'delete') {
            const id = req.query.id || req.body?.id;
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });

            await sql`DELETE FROM api_keys WHERE id = ${id}`;
            return res.status(200).json({ status: true, message: "Key terhapus" });
        }

        // --- ACTION: GET ALL KEYS FOR FRONTEND ---
        if (action === 'list') {
            const keys = await sql`SELECT * FROM api_keys ORDER BY id DESC`;
            return res.status(200).json({ status: true, data: keys });
        }

        // --- VALIDASI VIA METODE POST (UNTUK HTTP INJECTOR / CLIENT APP) ---
        if (req.method === 'POST') {
            const apiKey = req.body?.key || req.body?.api_key;

            if (!apiKey) {
                return res.status(400).json({
                    status: false,
                    valid: false,
                    message: "Payload JSON 'key' wajib diisi dalam body request POST!"
                });
            }

            const rows = await sql`SELECT * FROM api_keys WHERE key_value = ${apiKey}`;

            if (rows.length === 0) {
                return res.status(404).json({
                    status: false,
                    valid: false,
                    message: "API Key tidak terdaftar di database!"
                });
            }

            const keyData = rows[0];
            const isExpired = new Date(keyData.expired_at).getTime() < Date.now();

            if (isExpired) {
                return res.status(403).json({
                    status: false,
                    valid: false,
                    message: "API Key telah kadaluarsa (Expired)!",
                    expiredAt: keyData.expired_at
                });
            }

            return res.status(200).json({
                status: true,
                valid: true,
                message: "API Key Valid!",
                label: keyData.label,
                expiredAt: keyData.expired_at
            });
        }

    } catch (error) {
        return res.status(500).json({ status: false, message: "Database Error: " + error.message });
    }
}
