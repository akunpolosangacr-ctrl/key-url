import { neon } from '@neondatabase/serverless';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const dbUrl = process.env.STORAGE_URL || process.env.DATABASE_URL;
    if (!dbUrl) {
        return res.status(500).json({ status: false, message: "Database URL tidak terhubung!" });
    }

    const sql = neon(dbUrl);

    try {
        await sql`
            CREATE TABLE IF NOT EXISTS api_keys (
                id SERIAL PRIMARY KEY,
                label VARCHAR(255) NOT NULL,
                key_value VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expired_at TIMESTAMP NOT NULL,
                active_days INT NOT NULL,
                device_limit INT DEFAULT 1,
                hwid_list TEXT DEFAULT '[]'
            );
        `;

        // 🔒 PROTECTED PAGE UNTUK BROWSER (GET)
        if (req.method === 'GET' && !req.query.action) {
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            return res.status(200).send(`
                <!DOCTYPE html>
                <html lang="id">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Protected System</title>
                    <style>
                        * { margin:0; padding:0; box-sizing:border-box; font-family: sans-serif; }
                        body { background-color: #0b0f19; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; padding: 20px; }
                        .card { background-color: #111827; border: 1px solid #1e293b; border-radius: 20px; padding: 40px 30px; text-align: center; max-width: 360px; width: 100%; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
                        .icon-wrap { width: 64px; height: 64px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 20px auto; color: #ef4444; }
                        h1 { font-size: 1.4rem; color: #f8fafc; font-weight: 700; letter-spacing: 2px; margin-bottom: 8px; }
                        p { font-size: 0.85rem; color: #64748b; line-height: 1.5; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="icon-wrap">
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        </div>
                        <h1>PROTECTED</h1>
                        <p>Access Restricted. System Encrypted.</p>
                    </div>
                </body>
                </html>
            `);
        }

        const action = req.query.action || req.body?.action;

        // ACTION 1: CREATE KEY
        if (action === 'create') {
            const { label, days, custom_key, limit } = req.body || {};
            const activeDays = parseInt(days) || 30;
            const deviceLimit = parseInt(limit) || 1;
            const keyLabel = label || 'Untitled Key';

            let keyValue = (custom_key && custom_key.trim() !== '') ? custom_key.trim() : '';
            if (!keyValue) {
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                keyValue = 'vdb_';
                for (let i = 0; i < 32; i++) keyValue += chars.charAt(Math.floor(Math.random() * chars.length));
            }

            const checkExist = await sql`SELECT id FROM api_keys WHERE key_value = ${keyValue}`;
            if (checkExist.length > 0) {
                return res.status(400).json({ status: false, message: "Key sudah terpakai di database!" });
            }

            const expiredAt = new Date(Date.now() + activeDays * 24 * 60 * 60 * 1000);

            const result = await sql`
                INSERT INTO api_keys (label, key_value, expired_at, active_days, device_limit, hwid_list)
                VALUES (${keyLabel}, ${keyValue}, ${expiredAt.toISOString()}, ${activeDays}, ${deviceLimit}, '[]')
                RETURNING *;
            `;
            return res.status(200).json({ status: true, message: "Key tersimpan!", data: result[0] });
        }

        // ACTION 2: DELETE KEY
        if (action === 'delete') {
            const id = req.query.id || req.body?.id;
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });
            await sql`DELETE FROM api_keys WHERE id = ${id}`;
            return res.status(200).json({ status: true, message: "Key terhapus" });
        }

        // ACTION 3: RESET HWID
        if (action === 'reset_hwid') {
            const { id, target_hwid } = req.body || req.query;
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });

            const rows = await sql`SELECT hwid_list FROM api_keys WHERE id = ${id}`;
            if (rows.length === 0) return res.status(404).json({ status: false, message: "Key tidak ditemukan" });

            let hwids = JSON.parse(rows[0].hwid_list || '[]');
            if (target_hwid) {
                hwids = hwids.filter(h => h !== target_hwid);
            } else {
                hwids = [];
            }

            await sql`UPDATE api_keys SET hwid_list = ${JSON.stringify(hwids)} WHERE id = ${id}`;
            return res.status(200).json({ status: true, message: "HWID direset!", hwids });
        }

        // ACTION 4: LIST KEYS
        if (action === 'list') {
            const keys = await sql`SELECT * FROM api_keys ORDER BY id DESC`;
            return res.status(200).json({ status: true, data: keys });
        }

        // --- VALIDASI VIA POST (LGL / GAME GUARDIAN) ---
        if (req.method === 'POST') {
            const apiKey = req.body?.key || req.body?.api_key;
            const hwid = req.body?.hwid || req.body?.device_id || 'UNKNOWN_DEVICE';

            if (!apiKey) {
                return res.status(400).json({ status: false, valid: false, message: "API Key wajib diisi!" });
            }

            const rows = await sql`SELECT * FROM api_keys WHERE key_value = ${apiKey}`;
            if (rows.length === 0) {
                return res.status(404).json({ status: false, valid: false, message: "API Key tidak terdaftar!" });
            }

            const keyData = rows[0];
            const isExpired = new Date(keyData.expired_at).getTime() < Date.now();
            if (isExpired) {
                return res.status(403).json({ status: false, valid: false, message: "API Key sudah KADALUARSA (Expired)!" });
            }

            let hwidList = JSON.parse(keyData.hwid_list || '[]');
            const deviceLimit = keyData.device_limit || 1;

            const isRegistered = hwidList.includes(hwid);

            // Jika device baru & slot masih ada, daftarkan otomatis
            if (!isRegistered) {
                if (hwidList.length >= deviceLimit) {
                    return res.status(403).json({
                        status: false,
                        valid: false,
                        message: `Batas limit device tercapai (${hwidList.length}/${deviceLimit})!`
                    });
                }
                hwidList.push(hwid);
                await sql`UPDATE api_keys SET hwid_list = ${JSON.stringify(hwidList)} WHERE id = ${keyData.id}`;
            }

            return res.status(200).json({
                status: true,
                valid: true,
                message: "API Key Valid!",
                label: keyData.label,
                devices: `${hwidList.length}/${deviceLimit}`,
                expiredAt: keyData.expired_at
            });
        }

    } catch (error) {
        return res.status(500).json({ status: false, message: "Database Error: " + error.message });
    }
}
