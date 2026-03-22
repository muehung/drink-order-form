/**
 * 珍珠奶茶屋 — Order API Server
 * Node.js (純內建模組，不需任何 npm package)
 * 
 * 資安補強：
 *  - Helmet 式手動安全標頭
 *  - Rate Limiting（IP + Session Token）
 *  - Input 驗證 + XSS sanitize
 *  - CORS 白名單
 *  - Request Body Size 限制
 *  - JSON 解析防爆
 *  - 訂單 ID 不可預測（crypto.randomBytes）
 *  - 敏感資料 Log Masking
 *  - HTTPS 建議（可搭配 nginx）
 */

'use strict';

const http    = require('http');
const crypto  = require('crypto');
const path    = require('path');
const fs      = require('fs');

/* ─────────────────────────────────
   CONFIG
───────────────────────────────── */
const PORT            = process.env.PORT || 3000;
const MAX_BODY_BYTES  = 10 * 1024; // 10 KB

// CORS 白名單：開發時允許 Live Server，正式部署改用環境變數
const ALLOWED_ORIGINS = process.env.ORIGINS
  ? process.env.ORIGINS.split(',').map(s => s.trim())
  : [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:5500',
      'http://127.0.0.1:5500',
    ];

// Rate limit: per IP，每 30 秒最多 5 次 POST
const rateLimitStore = new Map(); // ip -> [timestamps]
const RATE_WINDOW_MS = 30_000;
const RATE_MAX       = 5;

// Session token store（防重複送出）
const usedTokens = new Set();
const TOKEN_TTL  = 5 * 60 * 1000; // 5 min

/* ─────────────────────────────────
   SECURITY HEADERS
───────────────────────────────── */
const securityHeaders = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'X-XSS-Protection':          '1; mode=block',
  'Referrer-Policy':           'no-referrer',
  'Permissions-Policy':        'geolocation=(), camera=(), microphone=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:;",
  'Cache-Control':             'no-store',
};

const addSecurityHeaders = res => {
  Object.entries(securityHeaders).forEach(([k, v]) => res.setHeader(k, v));
};

/* ─────────────────────────────────
   RATE LIMITER
───────────────────────────────── */
const checkRateLimit = ip => {
  const now = Date.now();
  let times = (rateLimitStore.get(ip) || []).filter(t => now - t < RATE_WINDOW_MS);
  if (times.length >= RATE_MAX) return false;
  times.push(now);
  rateLimitStore.set(ip, times);
  return true;
};

// 定期清理過期 IP
setInterval(() => {
  const now = Date.now();
  for (const [ip, times] of rateLimitStore.entries()) {
    const valid = times.filter(t => now - t < RATE_WINDOW_MS);
    if (!valid.length) rateLimitStore.delete(ip);
    else rateLimitStore.set(ip, valid);
  }
}, 60_000);

/* ─────────────────────────────────
   SANITIZE HELPERS
───────────────────────────────── */
const sanitize = (str, maxLen = 200) =>
  typeof str === 'string'
    ? str.replace(/[<>"'`]/g, '').trim().substring(0, maxLen)
    : '';

const maskPhone = phone =>
  typeof phone === 'string' && phone.length >= 4
    ? phone.slice(0, 4) + '****' + phone.slice(-2)
    : '***';

/* ─────────────────────────────────
   VALIDATION
───────────────────────────────── */
const VALID_DRINK_IDS = ['bbt','mgt','taro','brown','mango','lemon','pass','oolong'];
const VALID_SIZES     = ['M','L','XL'];
const VALID_TOPPINGS  = ['none','pearl','jelly','pudding','grass_jelly'];
const VALID_ICE       = ['正常冰','少冰','微冰','去冰','熱飲'];
const VALID_SUGAR     = ['全糖','七分糖','半糖','三分糖','無糖'];
const VALID_MODES     = ['delivery','pickup'];

const validateOrder = body => {
  const errors = [];

  // customer
  const { customer, deliveryMode, items, totalAmount } = body;
  if (!customer || typeof customer !== 'object') return ['缺少顧客資訊'];

  const name = sanitize(customer.name, 30);
  if (!name || name.length < 2) errors.push('姓名不合法');

  const phone = (customer.phone || '').replace(/\D/g, '');
  if (!/^09\d{8}$/.test(phone)) errors.push('電話格式不合法');

  if (deliveryMode === 'delivery') {
    const addr = sanitize(customer.address, 100);
    if (!addr || addr.length < 10) errors.push('地址不合法');
  }

  if (!VALID_MODES.includes(deliveryMode)) errors.push('取餐方式不合法');

  // items
  if (!Array.isArray(items) || items.length === 0) {
    errors.push('購物車是空的');
    return errors;
  }
  if (items.length > 50) errors.push('單次最多 50 項');

  let calcTotal = 0;
  items.forEach((item, idx) => {
    const prefix = `第 ${idx+1} 項：`;
    if (!VALID_DRINK_IDS.includes(item.id))   errors.push(prefix + '不合法飲料');
    if (!VALID_SIZES.includes(item.size))      errors.push(prefix + '不合法尺寸');
    if (!VALID_TOPPINGS.includes(item.topping)) errors.push(prefix + '不合法加料');
    if (!VALID_ICE.includes(item.ice))         errors.push(prefix + '不合法冰塊');
    if (!VALID_SUGAR.includes(item.sugar))     errors.push(prefix + '不合法甜度');
    const qty = parseInt(item.qty);
    if (!qty || qty < 1 || qty > 20) errors.push(prefix + '數量超出範圍');
    const unit = parseInt(item.unitPrice);
    if (!unit || unit < 0 || unit > 500) errors.push(prefix + '單價異常');
    calcTotal += (unit || 0) * (qty || 0);
  });

  // 驗證前端傳來的 totalAmount 與後端計算是否一致（防竄改）
  if (Math.abs(calcTotal - parseInt(totalAmount)) > 0) {
    errors.push('總金額與明細不符，請重新下單');
  }

  return errors;
};

/* ─────────────────────────────────
   READ BODY
───────────────────────────────── */
const readBody = (req) => new Promise((resolve, reject) => {
  let data = '';
  let bytes = 0;
  req.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      reject(new Error('BODY_TOO_LARGE'));
      req.destroy();
      return;
    }
    data += chunk;
  });
  req.on('end', () => {
    try {
      resolve(JSON.parse(data));
    } catch {
      reject(new Error('INVALID_JSON'));
    }
  });
  req.on('error', reject);
});

/* ─────────────────────────────────
   orders.json 持久化儲存
───────────────────────────────── */
const ORDERS_FILE = path.join(__dirname, 'orders.json');

// 啟動時讀入，讀不到就從空陣列開始
let orders = [];
try {
  const raw = fs.readFileSync(ORDERS_FILE, 'utf8');
  orders = JSON.parse(raw);
  console.log(`[STORE] 已載入 ${orders.length} 筆歷史訂單`);
} catch {
  orders = [];
  console.log('[STORE] orders.json 不存在，從空白開始');
}

// 寫檔（非同步，避免阻塞請求）
const flushOrders = () => {
  fs.writeFile(ORDERS_FILE, JSON.stringify(orders, null, 2), 'utf8', err => {
    if (err) console.error('[STORE] 寫檔失敗：', err.message);
  });
};

const saveOrder = order => {
  orders.push(order);
  flushOrders();
  // log 時遮蔽電話
  const safe = { ...order, customer: { ...order.customer, phone: maskPhone(order.customer.phone) } };
  console.log('[ORDER]', JSON.stringify(safe));
};

/* ─────────────────────────────────
   GENERATE SECURE ORDER ID
───────────────────────────────── */
const generateOrderId = () =>
  'BO-' + crypto.randomBytes(4).toString('hex').toUpperCase();

/* ─────────────────────────────────
   RESPONSES
───────────────────────────────── */
const sendJson = (res, status, body) => {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
};

const sendError = (res, status, message) =>
  sendJson(res, status, { success: false, message });

/* ─────────────────────────────────
   SERVE STATIC (index.html)
───────────────────────────────── */
const serveStatic = (req, res) => {
  const safePath = path.normalize(req.url.split('?')[0]);
  // 只允許根路徑
  if (safePath !== '/' && safePath !== '/index.html') {
    sendError(res, 404, '找不到頁面');
    return;
  }
  const filePath = path.join(__dirname, 'index.html');
  fs.readFile(filePath, (err, data) => {
    if (err) { sendError(res, 500, '伺服器錯誤'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(data);
  });
};

/* ─────────────────────────────────
   CORS CHECK
───────────────────────────────── */
const checkCors = (req, res) => {
  const origin = req.headers['origin'] || '';
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    sendError(res, 403, 'CORS 不允許此來源');
    return false;
  }
  if (origin) {
    // 回傳實際請求的 origin（才能通過瀏覽器的 CORS 驗證）
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Requested-With, X-Session-Token');
    res.setHeader('Vary', 'Origin');
  }
  return true;
};

/* ─────────────────────────────────
   MAIN REQUEST HANDLER
───────────────────────────────── */
const server = http.createServer(async (req, res) => {
  addSecurityHeaders(res);

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  const { method, url } = req;

  // OPTIONS preflight
  if (method === 'OPTIONS') {
    checkCors(req, res);
    res.writeHead(204);
    res.end();
    return;
  }

  // favicon — 避免 404 雜訊
  if (method === 'GET' && url === '/favicon.ico') {
    res.writeHead(204); res.end(); return;
  }

  // Static — 訂單查看頁
  if (method === 'GET' && (url === '/orders' || url === '/orders.html')) {
    const filePath = path.join(__dirname, 'orders.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { sendError(res, 500, '找不到訂單查看頁面'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // Static
  if (method === 'GET' && (url === '/' || url === '/index.html')) {
    serveStatic(req, res);
    return;
  }

  // ── POST /api/orders ──
  if (method === 'POST' && url === '/api/orders') {
    if (!checkCors(req, res)) return;

    // CSRF-like check
    const xRequested = req.headers['x-requested-with'];
    if (xRequested !== 'XMLHttpRequest') {
      sendError(res, 403, '非法請求來源');
      return;
    }

    // Content-Type check
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('application/json')) {
      sendError(res, 415, '只接受 JSON');
      return;
    }

    // Rate limit
    if (!checkRateLimit(ip)) {
      res.setHeader('Retry-After', '30');
      sendError(res, 429, '請求太頻繁，請 30 秒後再試');
      return;
    }

    // Read body
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      const msg = e.message === 'BODY_TOO_LARGE' ? '請求內容過大' : 'JSON 格式錯誤';
      sendError(res, 400, msg);
      return;
    }

    // Idempotency token（防重複送出）
    const token = sanitize(body._token, 64);
    if (!token) { sendError(res, 400, '缺少安全 Token'); return; }
    if (usedTokens.has(token)) {
      sendJson(res, 200, { success: true, message: '訂單已成立（重複請求）', orderId: '（已建立）' });
      return;
    }
    usedTokens.add(token);
    setTimeout(() => usedTokens.delete(token), TOKEN_TTL);

    // Validate
    const errors = validateOrder(body);
    if (errors.length) {
      sendJson(res, 422, { success: false, errors });
      return;
    }

    // Build clean order
    const orderId = generateOrderId();
    const order = {
      orderId,
      createdAt: new Date().toISOString(),
      ip,
      customer: {
        name:    sanitize(body.customer.name, 30),
        phone:   body.customer.phone.replace(/\D/g,''),
        address: body.deliveryMode === 'delivery' ? sanitize(body.customer.address, 100) : '自取',
        note:    sanitize(body.customer.note || '', 200),
      },
      deliveryMode: body.deliveryMode,
      items: body.items.map(item => ({
        id:        item.id,
        name:      sanitize(item.name, 30),
        size:      item.size,
        topping:   item.topping,
        ice:       item.ice,
        sugar:     item.sugar,
        qty:       parseInt(item.qty),
        unitPrice: parseInt(item.unitPrice),
        total:     parseInt(item.unitPrice) * parseInt(item.qty),
      })),
      totalAmount: body.items.reduce(
        (s, i) => s + parseInt(i.unitPrice) * parseInt(i.qty), 0
      ),
    };

    saveOrder(order);

    sendJson(res, 200, {
      success: true,
      orderId,
      message: `訂單已成立，單號 ${orderId}`,
      estimatedMinutes: body.deliveryMode === 'delivery' ? 30 : 15,
    });
    return;
  }

  // ── GET /api/orders — 查詢訂單清單
  // 支援 ?date=2026-03-16  ?mode=delivery  ?limit=20&offset=0
  if (method === 'GET' && url.startsWith('/api/orders')) {
    if (!checkCors(req, res)) return;
    const parsed   = new URL(url, `http://localhost`);
    const orderId  = parsed.pathname.split('/')[3]; // /api/orders/:id

    // 單筆查詢
    if (orderId) {
      const found = orders.find(o => o.orderId === orderId);
      if (!found) { sendError(res, 404, '找不到此訂單'); return; }
      const safe = { ...found, customer: { ...found.customer, phone: maskPhone(found.customer.phone) } };
      sendJson(res, 200, { success: true, order: safe });
      return;
    }

    // 清單查詢
    const filterDate = parsed.searchParams.get('date');   // YYYY-MM-DD
    const filterMode = parsed.searchParams.get('mode');   // delivery | pickup
    const limit      = Math.min(parseInt(parsed.searchParams.get('limit')  || '50'), 100);
    const offset     = Math.max(parseInt(parsed.searchParams.get('offset') || '0'), 0);

    let result = [...orders];

    if (filterDate) {
      result = result.filter(o => o.createdAt.startsWith(filterDate));
    }
    if (filterMode && ['delivery','pickup'].includes(filterMode)) {
      result = result.filter(o => o.deliveryMode === filterMode);
    }

    // 最新的排前面
    result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    const total   = result.length;
    const paged   = result.slice(offset, offset + limit);
    const safeList = paged.map(o => ({
      ...o,
      customer: { ...o.customer, phone: maskPhone(o.customer.phone) },
    }));

    sendJson(res, 200, {
      success: true,
      total,
      limit,
      offset,
      orders: safeList,
    });
    return;
  }

  // ── GET /status — serve status.html
  if (method === 'GET' && url.startsWith('/status')) {
    const filePath = path.join(__dirname, 'status.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { sendError(res, 500, '找不到狀態頁面'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // ── GET /api/order-status/:id — SSE 狀態推送
  if (method === 'GET' && url.startsWith('/api/order-status/')) {
    if (!checkCors(req, res)) return;

    const orderId = url.split('/')[3]?.split('?')[0];
    const order   = orders.find(o => o.orderId === orderId);
    if (!order) { sendError(res, 404, '找不到訂單'); return; }

    // SSE headers
    res.writeHead(200, {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no',          // nginx 不緩衝
      'Access-Control-Allow-Origin': res.getHeader('Access-Control-Allow-Origin') || '*',
    });

    const send = (status, extra = {}) => {
      const payload = JSON.stringify({ status, orderId, ...extra });
      res.write(`event: status\ndata: ${payload}\n\n`);
    };

    const mode = order.deliveryMode; // 'delivery' | 'pickup'

    // 時間軸（毫秒）
    //  0s  → confirmed（立即，前端自己處理）
    // 10s  → preparing
    // 20s  → delivering
    // 33s  → done（外送動畫13秒後）
    const timeline = mode === 'delivery'
      ? [
          { delay: 10_000, status: 'preparing'  },
          { delay: 20_000, status: 'delivering' },
          { delay: 33_000, status: 'done'       },
        ]
      : [
          { delay: 10_000, status: 'preparing'  },
          { delay: 20_000, status: 'delivering' },  // 「備餐完成」
          { delay: 30_000, status: 'done'       },
        ];

    // 送出初始 confirmed
    send('confirmed');

    const timers = timeline.map(({ delay, status }) =>
      setTimeout(() => {
        try { send(status); } catch {}
        if (status === 'done') {
          setTimeout(() => { try { res.end(); } catch {} }, 500);
        }
      }, delay)
    );

    // 客戶端斷線時清除所有 timer
    req.on('close', () => timers.forEach(clearTimeout));
    return;
  }

  sendError(res, 404, '找不到此路由');
});

server.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   🧋 珍珠奶茶屋 Order Server                 ║
║   訂單頁面   http://localhost:${PORT}            ║
║   訂單管理   http://localhost:${PORT}/orders     ║
║   狀態追蹤   http://localhost:${PORT}/status?id=XXX ║
║   訂單 API   http://localhost:${PORT}/api/orders ║
╚══════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => { server.close(() => process.exit(0)); });
process.on('SIGINT',  () => { server.close(() => process.exit(0)); });