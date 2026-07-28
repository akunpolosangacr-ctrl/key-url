import { neon } from '@neondatabase/serverless';

export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const dbUrl = process.env.STORAGE_URL || process.env.DATABASE_URL;
    if (!dbUrl) {
        return res.status(500).json({ status: false, message: "Database URL tidak ditemukan!" });
    }

    const sql = neon(dbUrl);

    // Dapatkan Real IP Pengunjung
    const rawIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const clientIp = rawIp.split(',')[0].trim();

    try {
        // Auto Table Setup
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
        await sql`
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip VARCHAR(100) PRIMARY KEY,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await sql`
            CREATE TABLE IF NOT EXISTS web_tracking_logs (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(100) NOT NULL,
                user_agent TEXT,
                path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;

        try {
            await sql`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS device_limit INT DEFAULT 1;`;
            await sql`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS hwid_list TEXT DEFAULT '[]';`;
        } catch (e) {}

        // CEK STATS BLOKIR IP PENGUNJUNG
        const checkBlocked = await sql`SELECT ip FROM blocked_ips WHERE ip = ${clientIp}`;
        if (checkBlocked.length > 0) {
            if (req.method === 'GET' && !req.query.action) {
                res.setHeader('Content-Type', 'text/html; charset=utf-8');
                return res.status(403).send(`
                    <!DOCTYPE html>
                    <html lang="id">
                    <head><meta charset="UTF-8"><title>IP Blocked</title>
                    <style>body{background:#0b0f19;color:#ef4444;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;margin:0;}
                    .box{border:1px solid #ef4444;padding:30px;border-radius:16px;text-align:center;background:#111827;}</style></head>
                    <body><div class="box"><h1>🚫 ACCESS DENIED</h1><p>IP Anda (${clientIp}) telah diblokir oleh Administrator.</p></div></body>
                    </html>
                `);
            }
            return res.status(403).json({ status: false, message: `IP Anda (${clientIp}) diblokir!` });
        }

        const action = req.query.action || req.body?.action;

        // CATAT TRACKING LOG JIKA AKSES DARI BROWSER UTAMA
        if (req.method === 'GET' && !action) {
            try {
                const userAgent = req.headers['user-agent'] || 'Unknown';
                await sql`INSERT INTO web_tracking_logs (ip, user_agent, path) VALUES (${clientIp}, ${userAgent}, ${req.url});`;
            } catch (e) {}

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
                        .card { background-color: #111827; border: 1px solid #1e293b; border-radius: 20px; padding: 48px 32px; text-align: center; max-width: 360px; width: 100%; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }
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

        // ACTION: GET TRACKING LOGS
        if (action === 'get_tracking') {
            const logs = await sql`SELECT * FROM web_tracking_logs ORDER BY id DESC LIMIT 50`;
            return res.status(200).json({ status: true, data: logs });
        }

        // ACTION: BLOCK IP
        if (action === 'block_ip') {
            const targetIp = req.query.ip || req.body?.ip;
            if (!targetIp) return res.status(400).json({ status: false, message: "IP diperlukan" });
            await sql`INSERT INTO blocked_ips (ip) VALUES (${targetIp}) ON CONFLICT DO NOTHING;`;
            return res.status(200).json({ status: true, message: `IP ${targetIp} berhasil diblokir!` });
        }

        // ACTION: UNBLOCK IP
        if (action === 'unblock_ip') {
            const targetIp = req.query.ip || req.body?.ip;
            if (!targetIp) return res.status(400).json({ status: false, message: "IP diperlukan" });
            await sql`DELETE FROM blocked_ips WHERE ip = ${targetIp}`;
            return res.status(200).json({ status: true, message: `IP ${targetIp} berhasil dibuka blokirnya!` });
        }

        // ACTION: GET BLOCKED IPS
        if (action === 'get_blocked') {
            const list = await sql`SELECT * FROM blocked_ips ORDER BY blocked_at DESC`;
            return res.status(200).json({ status: true, data: list });
        }

        // ACTION: CREATE KEY
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

        // ACTION: UPDATE KEY
        if (action === 'update_key') {
            const { id, add_days, new_limit } = req.body || {};
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });

            const rows = await sql`SELECT expired_at, active_days, device_limit FROM api_keys WHERE id = ${id}`;
            if (rows.length === 0) return res.status(404).json({ status: false, message: "Key tidak ditemukan" });

            const keyData = rows[0];
            const currentExpiredMs = new Date(keyData.expired_at).getTime();
            const nowMs = Date.now();

            const daysToAdd = parseInt(add_days) || 0;
            const addedMs = daysToAdd * 24 * 60 * 60 * 1000;

            let baseTime = currentExpiredMs < nowMs ? nowMs : currentExpiredMs;
            let newExpiredAt = new Date(baseTime + addedMs);

            let remainingMs = newExpiredAt.getTime() - nowMs;
            let updatedDays = Math.max(1, Math.ceil(remainingMs / (1000 * 60 * 60 * 24)));
            let updatedLimit = parseInt(new_limit) || keyData.device_limit;

            await sql`
                UPDATE api_keys 
                SET expired_at = ${newExpiredAt.toISOString()},
                    active_days = ${updatedDays},
                    device_limit = ${updatedLimit}
                WHERE id = ${id}
            `;

            return res.status(200).json({ status: true, message: "Key berhasil diperbarui!" });
        }

        // ACTION: DELETE KEY
        if (action === 'delete') {
            const id = req.query.id || req.body?.id;
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });
            await sql`DELETE FROM api_keys WHERE id = ${id}`;
            return res.status(200).json({ status: true, message: "Key terhapus" });
        }

        // ACTION: RESET HWID DEVICE
        if (action === 'reset_hwid') {
            const { id, target_hwid } = req.body || req.query;
            if (!id) return res.status(400).json({ status: false, message: "ID diperlukan" });

            const rows = await sql`SELECT hwid_list FROM api_keys WHERE id = ${id}`;
            if (rows.length === 0) return res.status(404).json({ status: false, message: "Key tidak ditemukan" });

            let hwids = [];
            try { hwids = JSON.parse(rows[0].hwid_list || '[]'); } catch (e) { hwids = []; }

            if (target_hwid) {
                hwids = hwids.filter(h => h !== target_hwid);
            } else {
                hwids = [];
            }

            await sql`UPDATE api_keys SET hwid_list = ${JSON.stringify(hwids)} WHERE id = ${id}`;
            return res.status(200).json({ status: true, message: "HWID direset!", hwids });
        }

        // ACTION: GET SINGLE KEY DETAILS
        if (action === 'get_key') {
            const id = req.query.id;
            const rows = await sql`SELECT * FROM api_keys WHERE id = ${id}`;
            if (rows.length === 0) return res.status(404).json({ status: false, message: "Data tidak ada" });
            return res.status(200).json({ status: true, data: rows[0] });
        }

        // ACTION: LIST ALL KEYS
        if (action === 'list') {
            const keys = await sql`SELECT * FROM api_keys ORDER BY id DESC`;
            return res.status(200).json({ status: true, data: keys });
        }

        // VALIDASI POST (CLIENT/BOT)
        if (req.method === 'POST') {
            const apiKey = req.body?.key || req.body?.api_key;
            const hwid = req.body?.hwid || req.body?.device_id || 'UNKNOWN_DEVICE';

            if (!apiKey) return res.status(400).json({ status: false, valid: false, message: "API Key wajib diisi!" });

            const rows = await sql`SELECT * FROM api_keys WHERE key_value = ${apiKey}`;
            if (rows.length === 0) return res.status(404).json({ status: false, valid: false, message: "API Key tidak terdaftar!" });

            const keyData = rows[0];
            const isExpired = new Date(keyData.expired_at).getTime() < Date.now();
            if (isExpired) return res.status(403).json({ status: false, valid: false, message: "API Key telah KADALUARSA!" });

            let hwidList = [];
            try { hwidList = JSON.parse(keyData.hwid_list || '[]'); } catch (e) { hwidList = []; }
            const deviceLimit = keyData.device_limit || 1;

            if (!hwidList.includes(hwid)) {
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
