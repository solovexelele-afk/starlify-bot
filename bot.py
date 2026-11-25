"""Starlify bot: Mini App кошелька, уведомления о поступлениях и админка.

Переменные окружения:
  TELEGRAM_BOT_TOKEN  — токен из @BotFather (задаётся в Render вручную)
  DATABASE_URL        — Postgres (на Render); без неё используется локальный SQLite
  ADMIN_USERNAMES     — логины админов через запятую, без @ (например: vexelele)
  WALLET_URL          — адрес кошелька Starlify (Mini App)
  TONAPI_KEY          — необязательно: ключ TonAPI, снимает лимит 1 запрос/сек
  RENDER_EXTERNAL_URL — подставляет Render; нужен для вебхука Telegram
Команда админки: /admin
"""
import base64, hashlib, html, json, os, sqlite3, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import requests

TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
DB_URL = os.environ.get('DATABASE_URL', '').strip()
ADMINS = {u.strip().lstrip('@').lower() for u in os.environ.get('ADMIN_USERNAMES', '').split(',') if u.strip()}
WALLET_URL = os.environ.get('WALLET_URL', 'https://vexelele-wallet.onrender.com/')
TONAPI_KEY = os.environ.get('TONAPI_KEY', '').strip()
PUBLIC_URL = os.environ.get('RENDER_EXTERNAL_URL', '').rstrip('/')
PORT = int(os.environ.get('PORT', '10000'))
DRY_RUN = os.environ.get('DRY_RUN') == '1'
WEBHOOK_SECRET = hashlib.sha256(('starlify:' + TOKEN).encode()).hexdigest()[:32] if TOKEN else ''
ALLOWED_ORIGINS = {'https://vexelele-wallet.onrender.com', 'http://localhost:5173', 'http://127.0.0.1:5173'}
MAX_ADDRS = 5
PAGE = 8
H = html.escape

def log(*a): print(time.strftime('%H:%M:%S'), *a, flush=True)
def now(): return int(time.time())

# ================================================================ база данных
class DB:
    def __init__(self):
        self.pg = DB_URL.startswith('postgres')
        self.lock = threading.Lock()
        if self.pg:
            import psycopg2
            self.conn = psycopg2.connect(DB_URL); self.conn.autocommit = True
        else:
            self.conn = sqlite3.connect(os.environ.get('SQLITE_PATH', 'starlify.db'), check_same_thread=False)
        auto = 'BIGSERIAL' if self.pg else 'INTEGER'
        self.run("""CREATE TABLE IF NOT EXISTS users (tg_id BIGINT PRIMARY KEY, username TEXT, first_name TEXT,
                    joined BIGINT, last_seen BIGINT, banned INTEGER DEFAULT 0, ban_reason TEXT)""")
        self.run(f"""CREATE TABLE IF NOT EXISTS addrs (id {auto} PRIMARY KEY, tg_id BIGINT, raw TEXT, last_lt BIGINT DEFAULT 0,
                    UNIQUE (tg_id, raw))""")
        self.run("""CREATE TABLE IF NOT EXISTS banned_addrs (raw TEXT PRIMARY KEY, reason TEXT, at BIGINT)""")
        self.run("""CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, notifications INTEGER DEFAULT 0)""")
        # кошельки, которые открывали Starlify Wallet (отмечаются при каждом открытии)
        self.run("""CREATE TABLE IF NOT EXISTS wallets (raw TEXT PRIMARY KEY, net TEXT, ver TEXT, src TEXT, tg_id BIGINT,
                    first_seen BIGINT, last_seen BIGINT, opens INTEGER DEFAULT 0)""")
        for col, ddl in (('notify', 'INTEGER DEFAULT 1'), ('scam_alerts', 'INTEGER DEFAULT 0'), ('min_ton', 'REAL DEFAULT 0')):
            try: self.run(f'ALTER TABLE users ADD COLUMN {col} {ddl}')
            except Exception: pass

    def run(self, sql, args=(), fetch=False):
        if self.pg: sql = sql.replace('?', '%s')
        with self.lock:
            cur = self.conn.cursor()
            try:
                cur.execute(sql, args)
                rows = cur.fetchall() if fetch else None
                if not self.pg: self.conn.commit()
                return rows
            finally: cur.close()

    def one(self, sql, args=()):
        r = self.run(sql, args, fetch=True); return r[0] if r else None

db = None

def tg_user_from_init(init):
    """Проверить подпись initData из Telegram Mini App и вернуть пользователя (или None)"""
    if not init or not TOKEN: return None
    try:
        import hmac
        pairs = dict(x.split('=', 1) for x in init.split('&') if '=' in x)
        from urllib.parse import unquote
        pairs = {k: unquote(v) for k, v in pairs.items()}
        got = pairs.pop('hash', '')
        check = '\n'.join(f'{k}={pairs[k]}' for k in sorted(pairs))
        secret = hmac.new(b'WebAppData', TOKEN.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(hmac.new(secret, check.encode(), hashlib.sha256).hexdigest(), got): return None
        if now() - int(pairs.get('auth_date', 0)) > 7 * 86400: return None
        return json.loads(pairs.get('user', 'null'))
    except Exception: return None

def wallet_seen(raw, net='mainnet', ver='', src='web', tg_user=None):
    t = now(); tg_id = None
    if tg_user and tg_user.get('id'):
        tg_id = int(tg_user['id']); touch_user(tg_user)
    if db.one('SELECT raw FROM wallets WHERE raw=?', (raw,)):
        db.run('UPDATE wallets SET last_seen=?, opens=opens+1, net=?, ver=COALESCE(NULLIF(?, ''), ver), src=?, tg_id=COALESCE(?, tg_id) WHERE raw=?',
               (t, net, ver, src, tg_id, raw))
    else:
        db.run('INSERT INTO wallets (raw, net, ver, src, tg_id, first_seen, last_seen, opens) VALUES (?,?,?,?,?,?,?,1)',
               (raw, net, ver, src, tg_id, t, t))

def bump_notifications(n=1):
    d = time.strftime('%Y-%m-%d')
    if db.one('SELECT day FROM daily WHERE day=?', (d,)): db.run('UPDATE daily SET notifications=notifications+? WHERE day=?', (n, d))
    else: db.run('INSERT INTO daily (day, notifications) VALUES (?,?)', (d, n))

# ================================================================ адреса TON
def _crc16(data: bytes) -> bytes:
    reg = 0
    for b in data:
        reg ^= b << 8
        for _ in range(8):
            reg = ((reg << 1) ^ 0x1021) if reg & 0x8000 else (reg << 1)
            reg &= 0xFFFF
    return reg.to_bytes(2, 'big')

def parse_address(s: str):
    s = (s or '').strip()
    if ':' in s:
        wc, _, h = s.partition(':')
        if wc in ('0', '-1') and len(h) == 64 and all(c in '0123456789abcdefABCDEF' for c in h): return f'{wc}:{h.lower()}'
        return None
    if len(s) != 48: return None
    try: b = base64.urlsafe_b64decode(s.replace('+', '-').replace('/', '_') + '==')
    except Exception: return None
    if len(b) != 36 or _crc16(b[:34]) != b[34:]: return None
    wc = b[1] - 256 if b[1] > 127 else b[1]
    return f'{wc}:{b[2:34].hex()}'

def friendly(raw: str) -> str:
    wc, _, h = raw.partition(':')
    body = bytes([0x51, int(wc) & 0xFF]) + bytes.fromhex(h)
    return base64.urlsafe_b64encode(body + _crc16(body)).decode()

def short(a: str) -> str: return a[:6] + '…' + a[-6:] if len(a) > 14 else a

def fmt(v: float, maxd=None) -> str:
    a = abs(v)
    d = maxd if maxd is not None else (2 if a >= 100 else 4 if a >= 1 else 6 if a >= 0.0001 else 9)
    s = f'{v:,.{d}f}'
    if '.' in s: s = s.rstrip('0').rstrip('.')
    return s.replace(',', ' ').replace('.', ',')

# ================================================================ TonAPI
_last_call = 0.0
_tapi_lock = threading.Lock()
def tonapi(path):
    global _last_call
    headers = {'Authorization': f'Bearer {TONAPI_KEY}'} if TONAPI_KEY else {}
    for attempt in range(4):
        with _tapi_lock:
            wait = (0.15 if TONAPI_KEY else 1.1) - (time.time() - _last_call)
            if wait > 0: time.sleep(wait)
            _last_call = time.time()
        r = requests.get('https://tonapi.io' + path, headers=headers, timeout=20)
        if r.status_code == 429: time.sleep(1.5 * (attempt + 1)); continue
        r.raise_for_status(); return r.json()
    raise RuntimeError('TonAPI перегружен')

_rate = {'usd': 0.0, 'at': 0}
def ton_usd():
    if time.time() - _rate['at'] > 300:
        try:
            _rate['usd'] = float(tonapi('/v2/rates?tokens=ton&currencies=usd')['rates']['TON']['prices']['USD']); _rate['at'] = time.time()
        except Exception: pass
    return _rate['usd']

def usd(v): return f'≈ ${fmt(v, 2)}' if v >= 0.01 else ''

def balance_of(raw):
    acc = tonapi(f'/v2/accounts/{raw}')
    jets = tonapi(f'/v2/accounts/{raw}/jettons?currencies=usd').get('balances', [])
    ton = int(acc.get('balance', 0)) / 1e9
    rows, total = [], ton * ton_usd()
    for j in jets:
        if j.get('balance') in (None, '0') or (j.get('jetton') or {}).get('verification') == 'blacklist': continue
        d = int(j['jetton'].get('decimals', 9)); amt = int(j['balance']) / 10 ** d
        price = ((j.get('price') or {}).get('prices') or {}).get('USD') or 0
        total += amt * price
        rows.append((j['jetton'].get('symbol') or '?', amt, amt * price))
    return ton, rows, total

def incoming_from_event(ev, raw):
    out = []
    for a in ev.get('actions', []):
        if a.get('status') != 'ok': continue
        t = a.get('TonTransfer') or a.get('JettonTransfer')
        if not t or (t.get('recipient') or {}).get('address', '').lower() != raw: continue
        if a.get('TonTransfer'):
            amount, sym, price = int(t['amount']) / 1e9, 'TON', ton_usd()
        else:
            j = t.get('jetton') or {}
            amount, sym = int(t['amount']) / 10 ** int(j.get('decimals', 9)), j.get('symbol') or 'токенов'
            price = 1.0 if sym in ('USD₮', 'USDT', 'jUSDT') else 0.0
        sender = t.get('sender') or {}
        out.append({'amount': amount, 'sym': sym, 'usd': amount * price, 'ton': sym == 'TON',
                    'from': sender.get('name') or (friendly(sender['address']) if sender.get('address') else '—'),
                    'comment': t.get('comment') or '', 'scam': bool(ev.get('is_scam') or sender.get('is_scam'))})
    return out

def latest_lt(raw):
    evs = tonapi(f'/v2/accounts/{raw}/events?limit=1').get('events', [])
    return int(evs[0]['lt']) if evs else 0

# ================================================================ Telegram
def tg(method, **params):
    if DRY_RUN:
        log('[DRY]', method, json.dumps(params, ensure_ascii=False)[:600]); return {'ok': True, 'result': {'message_id': 1}}
    try:
        r = requests.post(f'https://api.telegram.org/bot{TOKEN}/{method}', json=params, timeout=20)
        data = r.json()
    except Exception as e:
        log('tg error', method, e); return {'ok': False}
    if not data.get('ok') and 'message is not modified' not in str(data.get('description')): log('tg error', method, data.get('description'))
    return data

def send(chat, text, kb=None):
    p = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
    if kb: p['reply_markup'] = {'inline_keyboard': kb}
    return tg('sendMessage', **p)

def show(chat, msg_id, text, kb=None):
    """Обновить экран в том же сообщении (если можно), иначе прислать новое"""
    if msg_id:
        p = {'chat_id': chat, 'message_id': msg_id, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
        if kb: p['reply_markup'] = {'inline_keyboard': kb}
        r = tg('editMessageText', **p)
        if r.get('ok') or 'not modified' in str(r.get('description')): return r
    return send(chat, text, kb)

def B(text, data): return {'text': text, 'callback_data': data}
WALLET = {'text': '💼 Открыть кошелёк', 'web_app': {'url': WALLET_URL}}
def is_admin(u): return (u.get('username') or '').lower() in ADMINS

# ================================================================ пользователи
def touch_user(u):
    t = now()
    if db.one('SELECT tg_id FROM users WHERE tg_id=?', (u['id'],)):
        db.run('UPDATE users SET username=?, first_name=?, last_seen=? WHERE tg_id=?', (u.get('username'), u.get('first_name'), t, u['id']))
    else:
        db.run('INSERT INTO users (tg_id, username, first_name, joined, last_seen, banned, notify, scam_alerts, min_ton) VALUES (?,?,?,?,?,0,1,0,0)',
               (u['id'], u.get('username'), u.get('first_name'), t, t))
    return db.one('SELECT banned, ban_reason FROM users WHERE tg_id=?', (u['id'],))

def settings(tg_id):
    r = db.one('SELECT notify, scam_alerts, min_ton FROM users WHERE tg_id=?', (tg_id,))
    return {'notify': (r[0] if r else 1) != 0, 'scam': (r[1] if r else 0) != 0, 'min_ton': float(r[2] or 0) if r else 0.0}

def user_addrs(tg_id):
    return db.run('SELECT id, raw FROM addrs WHERE tg_id=? ORDER BY id', (tg_id,), fetch=True)

def find_user(token):
    token = (token or '').strip().lstrip('@')
    if not token: return None
    if token.lstrip('-').isdigit(): return db.one('SELECT tg_id, username, first_name, banned, ban_reason, joined, last_seen FROM users WHERE tg_id=?', (int(token),))
    return db.one('SELECT tg_id, username, first_name, banned, ban_reason, joined, last_seen FROM users WHERE lower(username)=?', (token.lower(),))

pending = {}   # chat -> {'t': 'bc'|'msg'|'find'|'reason'|'add', ...}

# ---------------------------------------------------------------- экраны пользователя
def scr_home(u):
    a = user_addrs(u['id'])
    text = (f'<b>Starlify Wallet</b>\n\n'
            f'TON-кошелёк прямо в Telegram: TON, USDT, NFT, обмен и подключение к сайтам.\n\n'
            + (f'Слежу за {len(a)} {"адресом" if len(a) == 1 else "адресами"} и пишу о каждом поступлении 🔔' if a else
               'Привяжи адрес кошелька, и я буду писать о каждом поступлении 🔔'))
    kb = [[WALLET], [B('💰 Баланс', 'm:bal'), B('📋 Мои адреса', 'm:addrs')],
          [B('➕ Привязать адрес', 'm:add'), B('⚙️ Уведомления', 'm:set')], [B('❓ Помощь', 'm:help')]]
    if is_admin(u): kb.append([B('🛠 Админка', 'ad:home')])
    return text, kb

def scr_addrs(u):
    a = user_addrs(u['id'])
    if not a: return 'Адресов пока нет.\n\nНажми «Привязать адрес» или просто пришли адрес кошелька сообщением.', [[B('➕ Привязать адрес', 'm:add')], [B('‹ Назад', 'm:home')]]
    text = '<b>Мои адреса</b>\n\n' + '\n'.join(f'{i + 1}. <code>{friendly(r)}</code>' for i, (_, r) in enumerate(a))
    kb = [[B(f'💰 {i + 1}. {short(friendly(r))}', f'a:bal:{aid}'), B('🗑', f'a:del:{aid}')] for i, (aid, r) in enumerate(a)]
    if len(a) < MAX_ADDRS: kb.append([B('➕ Привязать ещё', 'm:add')])
    kb.append([B('‹ Назад', 'm:home')])
    return text, kb

def balance_text(raw):
    ton, jets, total = balance_of(raw)
    lines = [f'<b>{short(friendly(raw))}</b>', f'💎 {fmt(ton)} TON {usd(ton * ton_usd())}']
    lines += [f'• {fmt(amt)} {H(sym)} {usd(v)}' for sym, amt, v in jets[:8]]
    lines.append(f'Итого: <b>${fmt(total, 2)}</b>')
    return '\n'.join(lines)

def scr_balance(u, aid=None):
    a = user_addrs(u['id'])
    if aid: a = [x for x in a if str(x[0]) == str(aid)]
    if not a: return 'Сначала привяжи адрес кошелька', [[B('➕ Привязать адрес', 'm:add')], [B('‹ Назад', 'm:home')]]
    try: body = '\n\n'.join(balance_text(r) for _, r in a)
    except Exception: body = 'Не удалось получить баланс, попробуй через минуту'
    return '<b>Баланс</b>\n\n' + body, [[WALLET], [B('🔄 Обновить', f'a:bal:{aid}' if aid else 'm:bal'), B('‹ Назад', 'm:home')]]

def scr_settings(u):
    s = settings(u['id'])
    mins = {0: 'все', 0.01: 'от 0,01 TON', 0.1: 'от 0,1 TON', 1: 'от 1 TON'}
    text = ('<b>Уведомления</b>\n\n'
            f'Поступления: {"включены ✅" if s["notify"] else "выключены 🔕"}\n'
            f'Мелкие суммы TON: {mins.get(s["min_ton"], "все")}\n'
            f'Скам-переводы: {"показывать с пометкой ⚠️" if s["scam"] else "не присылать"}')
    kb = [[B('🔕 Выключить' if s['notify'] else '🔔 Включить', 's:notify')],
          [B('Порог: ' + mins.get(s['min_ton'], 'все'), 's:min')],
          [B('Скам: ' + ('показывать' if s['scam'] else 'скрывать'), 's:scam')], [B('‹ Назад', 'm:home')]]
    return text, kb

HELP = ('<b>Помощь</b>\n\n'
        '💼 <b>Открыть кошелёк</b> — Starlify Wallet прямо в Telegram (кнопка «Кошелёк» внизу тоже его открывает)\n'
        '➕ <b>Привязать адрес</b> — пришли адрес TON-кошелька, и я буду писать о каждом поступлении\n'
        '💰 <b>Баланс</b> — TON и токены на привязанных адресах\n'
        '⚙️ <b>Уведомления</b> — включить, выключить, порог мелких сумм, скам\n\n'
        'Я вижу только публичный адрес. Секретные фразы и ПИН-коды никогда не спрашиваю')

def link_address(u, chat, raw, msg_id=None):
    a = [r for _, r in user_addrs(u['id'])]
    if raw in a: return show(chat, msg_id, 'Этот адрес уже привязан ✅', [[B('📋 Мои адреса', 'm:addrs')]])
    if len(a) >= MAX_ADDRS: return show(chat, msg_id, f'Можно привязать до {MAX_ADDRS} адресов. Удали лишний в «Мои адреса»', [[B('📋 Мои адреса', 'm:addrs')]])
    try: lt = latest_lt(raw)
    except Exception: lt = 0
    db.run('INSERT INTO addrs (tg_id, raw, last_lt) VALUES (?,?,?)', (u['id'], raw, lt))
    send(chat, f'✅ Адрес привязан\n<code>{friendly(raw)}</code>\n\nНапишу, как только на него придут TON или токены 🔔',
         [[WALLET], [B('💰 Баланс', 'm:bal'), B('📋 Мои адреса', 'm:addrs')]])

# ---------------------------------------------------------------- обработка сообщений
def on_message(m):
    if m['chat'].get('type') != 'private': return
    u = m.get('from') or {}; chat = m['chat']['id']
    banned = touch_user(u); admin = is_admin(u)
    if banned and banned[0] and not admin:
        send(chat, '⛔ Доступ к боту ограничен.' + (f'\nПричина: {H(banned[1])}' if banned[1] else '')); return
    text = (m.get('text') or '').strip()
    st = pending.get(chat)
    if st and text and not text.startswith('/'):
        if admin and st['t'] in ('bc', 'msg', 'find', 'reason', 'wreason'): return admin_input(chat, u, st, text)
        if st['t'] == 'add':
            pending.pop(chat, None)
            raw = parse_address(text)
            return link_address(u, chat, raw) if raw else send(chat, 'Это не адрес TON. Он начинается с UQ или EQ и состоит из 48 символов', [[B('‹ В меню', 'm:home')]])
    pending.pop(chat, None)
    cmd = text.split()[0].lower() if text else ''
    if cmd in ('/start', '/menu'):
        t, kb = scr_home(u); return send(chat, t, kb)
    if cmd == '/help': return send(chat, HELP, [[B('‹ В меню', 'm:home')]])
    if cmd == '/balance': t, kb = scr_balance(u); return send(chat, t, kb)
    if cmd == '/list': t, kb = scr_addrs(u); return send(chat, t, kb)
    if cmd == '/admin':
        if admin: t, kb = adm_home(); return send(chat, t, kb)
        return send(chat, 'Эта команда только для администраторов')
    if admin and cmd in ('/ban', '/unban', '/user', '/banaddr', '/unbanaddr', '/broadcast'): return admin_command(chat, u, text)
    raw = parse_address(text)
    if raw: return link_address(u, chat, raw)
    t, kb = scr_home(u); send(chat, 'Не понял 🙂 Пришли адрес TON-кошелька или выбери действие:', kb)

def on_callback(cq):
    u = cq.get('from') or {}; msg = cq.get('message') or {}; chat = msg.get('chat', {}).get('id'); mid = msg.get('message_id')
    data = cq.get('data', '')
    banned = touch_user(u); admin = is_admin(u)
    if banned and banned[0] and not admin:
        tg('answerCallbackQuery', callback_query_id=cq['id'], text='Доступ ограничен', show_alert=True); return
    if data.startswith('ad:'):
        tg('answerCallbackQuery', callback_query_id=cq['id'])
        if admin: admin_callback(chat, mid, u, data)
        return
    note = None
    if data == 'm:home': t, kb = scr_home(u)
    elif data == 'm:addrs': t, kb = scr_addrs(u)
    elif data == 'm:help': t, kb = HELP, [[B('‹ В меню', 'm:home')]]
    elif data == 'm:set': t, kb = scr_settings(u)
    elif data == 'm:add':
        pending[chat] = {'t': 'add'}
        t, kb = 'Пришли адрес TON-кошелька одним сообщением (UQ… или EQ…)', [[B('Отмена', 'm:home')]]
    elif data == 'm:bal' or data.startswith('a:bal:'):
        tg('answerCallbackQuery', callback_query_id=cq['id'], text='Загружаю баланс…'); note = 'answered'
        aid = data.split(':')[2] if data.startswith('a:bal:') and data.split(':')[2] not in ('', 'None') else None
        t, kb = scr_balance(u, aid)
    elif data.startswith('a:del:'):
        db.run('DELETE FROM addrs WHERE id=? AND tg_id=?', (int(data.split(':')[2]), u['id'])); t, kb = scr_addrs(u); note = 'Адрес удалён'
    elif data == 's:notify':
        db.run('UPDATE users SET notify=? WHERE tg_id=?', (0 if settings(u['id'])['notify'] else 1, u['id'])); t, kb = scr_settings(u)
    elif data == 's:scam':
        db.run('UPDATE users SET scam_alerts=? WHERE tg_id=?', (0 if settings(u['id'])['scam'] else 1, u['id'])); t, kb = scr_settings(u)
    elif data == 's:min':
        steps = [0, 0.01, 0.1, 1]; cur = settings(u['id'])['min_ton']
        nxt = steps[(steps.index(cur) + 1) % len(steps)] if cur in steps else 0
        db.run('UPDATE users SET min_ton=? WHERE tg_id=?', (nxt, u['id'])); t, kb = scr_settings(u)
    else: t, kb = scr_home(u)
    if note != 'answered': tg('answerCallbackQuery', callback_query_id=cq['id'], **({'text': note} if note else {}))
    show(chat, mid, t, kb)

# ================================================================ админка
def adm_home():
    n = db.one('SELECT count(*) FROM users')[0]
    day = db.one('SELECT count(*) FROM users WHERE last_seen>?', (now() - 86400,))[0]
    return (f'🛠 <b>Админка Starlify</b>\n\nПользователей: <b>{n}</b> · активны за сутки: <b>{day}</b>\n\nВыбери действие:',
            [[B('📊 Статистика', 'ad:stats'), B('👥 Пользователи', 'ad:users:0')],
             [B('💼 Кошельки', 'ad:wl:0'), B('🔎 Найти', 'ad:find')],
             [B('🚫 Забаненные', 'ad:banned')],
             [B('📣 Рассылка', 'ad:bc')], [B('‹ В меню', 'm:home')]])

def adm_stats():
    q = lambda sql, a=(): db.one(sql, a)[0]
    t = now()
    notif_today = db.one('SELECT notifications FROM daily WHERE day=?', (time.strftime('%Y-%m-%d'),))
    text = ('📊 <b>Статистика</b>\n\n'
            f'Пользователей: <b>{q("SELECT count(*) FROM users")}</b>\n'
            f'Новых за сутки: {q("SELECT count(*) FROM users WHERE joined>?", (t - 86400,))} · за неделю: {q("SELECT count(*) FROM users WHERE joined>?", (t - 7 * 86400,))}\n'
            f'Активны за сутки: {q("SELECT count(*) FROM users WHERE last_seen>?", (t - 86400,))}\n'
            f'Кошельков Starlify: {q("SELECT count(*) FROM wallets")} · открывали за сутки: {q("SELECT count(*) FROM wallets WHERE last_seen>?", (t - 86400,))}\n'
            f'Привязано адресов в боте: {q("SELECT count(*) FROM addrs")}\n'
            f'Уведомлений сегодня: {notif_today[0] if notif_today else 0}\n'
            f'Выключили уведомления: {q("SELECT count(*) FROM users WHERE notify=0")}\n'
            f'Забанено: {q("SELECT count(*) FROM users WHERE banned=1")} · заблокировано адресов: {q("SELECT count(*) FROM banned_addrs")}')
    return text, [[B('🔄 Обновить', 'ad:stats'), B('‹ Админка', 'ad:home')]]

def adm_wallets(page):
    total = db.one('SELECT count(*) FROM wallets')[0]
    day = db.one('SELECT count(*) FROM wallets WHERE last_seen>?', (now() - 86400,))[0]
    rows = db.run('SELECT w.raw, w.net, u.username, w.last_seen, (SELECT count(*) FROM banned_addrs b WHERE b.raw=w.raw) '
                  'FROM wallets w LEFT JOIN users u ON u.tg_id=w.tg_id ORDER BY w.last_seen DESC LIMIT ? OFFSET ?', (PAGE, page * PAGE), fetch=True)
    kb = [[B(('🚫 ' if r[4] else '') + short(friendly(r[0])) + (' · test' if r[1] == 'testnet' else '') + (f' · @{r[2]}' if r[2] else '')
             + ' · ' + time.strftime('%d.%m', time.localtime(r[3] or 0)), f'ad:w:{friendly(r[0])}')] for r in rows]
    nav = []
    if page > 0: nav.append(B('‹', f'ad:wl:{page - 1}'))
    if (page + 1) * PAGE < total: nav.append(B('›', f'ad:wl:{page + 1}'))
    if nav: kb.append(nav)
    kb.append([B('‹ Админка', 'ad:home')])
    text = (f'💼 <b>Кошельки Starlify</b> · {total}\nОткрывали за сутки: {day}\nСтраница {page + 1} из {max(1, -(-total // PAGE))}\n\n'
            'Здесь все адреса, которые открывали кошелёк (сайт, приложение или Mini App). Нажми на кошелёк, чтобы открыть карточку и забанить')
    return text, kb

def adm_wallet(raw):
    w = db.one('SELECT net, ver, src, tg_id, first_seen, last_seen, opens FROM wallets WHERE raw=?', (raw,))
    ban = db.one('SELECT reason, at FROM banned_addrs WHERE raw=?', (raw,))
    owners = db.run('SELECT DISTINCT u.tg_id, u.username, u.first_name FROM users u WHERE u.tg_id IN (SELECT tg_id FROM addrs WHERE raw=?) OR u.tg_id=?',
                    (raw, w[3] if w and w[3] else -1), fetch=True)
    fa = friendly(raw)
    lines = [f'💼 <b>Кошелёк</b>\n<code>{fa}</code>']
    if w:
        src = {'tg': 'Mini App в Telegram', 'app': 'приложение', 'web': 'сайт'}.get(w[2], w[2] or '—')
        lines.append(f'Сеть: {w[0]} · версия: {w[1] or "—"} · откуда: {src}\n'
                     f'Первый вход: {time.strftime("%d.%m.%Y %H:%M", time.localtime(w[4] or 0))}\n'
                     f'Последний: {time.strftime("%d.%m.%Y %H:%M", time.localtime(w[5] or 0))} · открытий: {w[6]}')
    else: lines.append('В кошельке Starlify этот адрес не открывали')
    if not w or w[0] != 'testnet':
        try:
            ton, jets, total = balance_of(raw)
            lines.append(f'Баланс: {fmt(ton)} TON' + ''.join(f', {fmt(a)} {H(s)}' for s, a, _ in jets[:3]) + f' · ${fmt(total, 2)}')
        except Exception: lines.append('Баланс: не удалось получить')
    lines.append('Telegram: ' + (', '.join(f'{H(o[2] or "—")}' + (f' @{H(o[1])}' if o[1] else '') + f' <code>{o[0]}</code>' for o in owners) or 'не связан'))
    lines.append('Статус: ' + (f'🚫 забанен' + (f' — {H(ban[0])}' if ban and ban[0] else '') if ban else '✅ активен'))
    kb = [[B('✅ Разбанить', f'ad:wunban:{fa}') if ban else B('🚫 Забанить кошелёк', f'ad:wban:{fa}')],
          [{'text': '🔍 Tonviewer', 'url': f'https://tonviewer.com/{fa}'}]]
    kb += [[B(f'👤 {(o[2] or str(o[0]))[:20]}', f'ad:u:{o[0]}')] for o in owners[:3]]
    kb.append([B('‹ Кошельки', 'ad:wl:0'), B('‹ Админка', 'ad:home')])
    return '\n'.join(lines), kb

def ban_wallet(raw, reason=''):
    db.run('DELETE FROM banned_addrs WHERE raw=?', (raw,))
    db.run('INSERT INTO banned_addrs (raw, reason, at) VALUES (?,?,?)', (raw, reason or None, now()))

def who(r): return f'{H(r[2] or "—")}' + (f' @{H(r[1])}' if r[1] else '')

def adm_users(page):
    total = db.one('SELECT count(*) FROM users')[0]
    rows = db.run('SELECT tg_id, username, first_name, banned FROM users ORDER BY joined DESC LIMIT ? OFFSET ?', (PAGE, page * PAGE), fetch=True)
    kb = [[B(('🚫 ' if r[3] else '') + (r[2] or str(r[0]))[:20] + (f' @{r[1]}' if r[1] else ''), f'ad:u:{r[0]}')] for r in rows]
    nav = []
    if page > 0: nav.append(B('‹', f'ad:users:{page - 1}'))
    if (page + 1) * PAGE < total: nav.append(B('›', f'ad:users:{page + 1}'))
    if nav: kb.append(nav)
    kb.append([B('‹ Админка', 'ad:home')])
    return f'👥 <b>Пользователи</b> · {total}\nСтраница {page + 1} из {max(1, -(-total // PAGE))}', kb

def adm_card(tg_id):
    r = find_user(str(tg_id))
    if not r: return 'Пользователь не найден', [[B('‹ Админка', 'ad:home')]]
    tgid, username, first_name, banned, reason, joined, last_seen = r
    a = user_addrs(tgid); s = settings(tgid)
    seen = {x for _, x in a}
    a = a + [(None, w[0]) for w in db.run('SELECT raw FROM wallets WHERE tg_id=?', (tgid,), fetch=True) if w[0] not in seen]
    text = (f'👤 <b>{H(first_name or "—")}</b>' + (f' @{H(username)}' if username else '') + f'\nid: <code>{tgid}</code>\n'
            f'С нами с {time.strftime("%d.%m.%Y", time.localtime(joined or 0))} · был {time.strftime("%d.%m %H:%M", time.localtime(last_seen or 0))}\n'
            f'Статус: {"🚫 забанен" + (" — " + H(reason) if reason else "") if banned else "✅ активен"}\n'
            f'Уведомления: {"вкл" if s["notify"] else "выкл"}\n\n<b>Адреса</b>\n' + ('\n'.join(f'<code>{friendly(x)}</code>' for _, x in a) or '—'))
    kb = [[B('✅ Разбанить', f'ad:unban:{tgid}') if banned else B('🚫 Забанить', f'ad:ban:{tgid}'), B('✉️ Написать', f'ad:msg:{tgid}')],
          *[[B(f'💼 {short(friendly(x))}', f'ad:w:{friendly(x)}')] for _, x in a[:5]],
          [B('‹ Пользователи', 'ad:users:0')]]
    return text, kb

def adm_banned():
    rows = db.run('SELECT tg_id, username, first_name, ban_reason FROM users WHERE banned=1 ORDER BY last_seen DESC LIMIT 20', fetch=True)
    ad = db.run('SELECT raw, reason FROM banned_addrs ORDER BY at DESC LIMIT 20', fetch=True)
    text = '🚫 <b>Забаненные</b>\n\n' + ('\n'.join(f'• {who(r)} <code>{r[0]}</code>' + (f' — {H(r[3])}' if r[3] else '') for r in rows) or 'Никого') \
           + '\n\n<b>Заблокированные адреса</b>\n' + ('\n'.join(f'• <code>{short(friendly(r[0]))}</code>' + (f' — {H(r[1])}' if r[1] else '') for r in ad) or '—') \
           + '\n\nЗаблокировать адрес: /banaddr адрес причина'
    kb = [[B(f'✅ {(r[2] or str(r[0]))[:18]}', f'ad:unban:{r[0]}')] for r in rows[:10]] \
         + [[B(f'💼 {short(friendly(r[0]))}', f'ad:w:{friendly(r[0])}')] for r in ad[:10]] + [[B('‹ Админка', 'ad:home')]]
    return text, kb

def do_ban(admin_chat, tg_id, reason=''):
    db.run('UPDATE users SET banned=1, ban_reason=? WHERE tg_id=?', (reason or None, tg_id))
    send(tg_id, '⛔ Доступ к боту ограничен.' + (f'\nПричина: {H(reason)}' if reason else ''))

def do_unban(tg_id):
    db.run('UPDATE users SET banned=0, ban_reason=NULL WHERE tg_id=?', (tg_id,))
    send(tg_id, '✅ Доступ к боту восстановлен', [[WALLET]])

def admin_callback(chat, mid, u, data):
    parts = data.split(':')
    if data == 'ad:home': t, kb = adm_home()
    elif data == 'ad:stats': t, kb = adm_stats()
    elif parts[1] == 'users': t, kb = adm_users(int(parts[2]))
    elif parts[1] == 'u': t, kb = adm_card(int(parts[2]))
    elif data == 'ad:banned': t, kb = adm_banned()
    elif parts[1] == 'wl': t, kb = adm_wallets(int(parts[2]))
    elif parts[1] in ('w', 'wban', 'wbanok', 'wunban'):
        raw = parse_address(parts[2])
        if not raw: t, kb = 'Неверный адрес', [[B('‹ Админка', 'ad:home')]]
        elif parts[1] == 'w': t, kb = adm_wallet(raw)
        elif parts[1] == 'wban':
            pending[chat] = {'t': 'wreason', 'raw': raw}
            t, kb = f'Бан кошелька <code>{friendly(raw)}</code>\n\nНапиши причину одним сообщением или нажми «Без причины»', \
                    [[B('Без причины', f'ad:wbanok:{parts[2]}'), B('Отмена', f'ad:w:{parts[2]}')]]
        elif parts[1] == 'wbanok': pending.pop(chat, None); ban_wallet(raw); t, kb = adm_wallet(raw)
        else: db.run('DELETE FROM banned_addrs WHERE raw=?', (raw,)); t, kb = adm_wallet(raw)
    elif parts[1] == 'ban':
        pending[chat] = {'t': 'reason', 'target': int(parts[2])}
        t, kb = 'Напиши причину бана одним сообщением или нажми «Без причины»', [[B('Без причины', f'ad:banok:{parts[2]}'), B('Отмена', f'ad:u:{parts[2]}')]]
    elif parts[1] == 'banok':
        pending.pop(chat, None); do_ban(chat, int(parts[2])); t, kb = adm_card(int(parts[2]))
    elif parts[1] == 'unban': do_unban(int(parts[2])); t, kb = adm_card(int(parts[2]))
    elif parts[1] == 'msg':
        pending[chat] = {'t': 'msg', 'target': int(parts[2])}
        t, kb = 'Напиши сообщение для пользователя. Оно придёт от имени бота', [[B('Отмена', f'ad:u:{parts[2]}')]]
    elif data == 'ad:find':
        pending[chat] = {'t': 'find'}; t, kb = 'Пришли @логин, id или адрес кошелька', [[B('Отмена', 'ad:home')]]
    elif data == 'ad:bc':
        pending[chat] = {'t': 'bc'}; t, kb = 'Пришли текст рассылки одним сообщением. Можно с эмодзи и переносами строк', [[B('Отмена', 'ad:home')]]
    elif data == 'ad:bc_go':
        st = pending.pop(chat, None)
        if not st or not st.get('text'): t, kb = 'Нет текста рассылки', [[B('‹ Админка', 'ad:home')]]
        else:
            threading.Thread(target=do_broadcast, args=(chat, st['text'], st.get('btn')), daemon=True).start()
            t, kb = '📣 Рассылка запущена, пришлю отчёт', [[B('‹ Админка', 'ad:home')]]
    elif data == 'ad:bc_btn':
        st = pending.get(chat) or {}; st['btn'] = not st.get('btn'); pending[chat] = st; return admin_bc_preview(chat, mid, st)
    elif data == 'ad:bc_no': pending.pop(chat, None); t, kb = adm_home()
    else: t, kb = adm_home()
    show(chat, mid, t, kb)

def admin_bc_preview(chat, mid, st):
    n = db.one('SELECT count(*) FROM users WHERE banned=0')[0]
    t = f'📣 <b>Предпросмотр</b> · получателей: {n}\n\n{H(st["text"])}' + ('\n\n[кнопка «Открыть кошелёк»]' if st.get('btn') else '')
    kb = [[B('✅ Отправить всем', 'ad:bc_go')], [B(('✓ ' if st.get('btn') else '') + 'Кнопка «Открыть кошелёк»', 'ad:bc_btn')], [B('Отмена', 'ad:bc_no')]]
    show(chat, mid, t, kb)

def admin_input(chat, u, st, text):
    if st['t'] == 'bc':
        st['text'] = text; pending[chat] = st; return admin_bc_preview(chat, None, st)
    pending.pop(chat, None)
    if st['t'] == 'msg':
        r = send(st['target'], f'✉️ <b>Сообщение от Starlify</b>\n\n{H(text)}')
        t, kb = adm_card(st['target'])
        return send(chat, ('✅ Отправлено\n\n' if r.get('ok') else '⚠️ Не доставлено (пользователь заблокировал бота?)\n\n') + t, kb)
    if st['t'] == 'wreason':
        ban_wallet(st['raw'], text.strip()); t, kb = adm_wallet(st['raw']); return send(chat, t, kb)
    if st['t'] == 'reason':
        do_ban(chat, st['target'], text.strip()); t, kb = adm_card(st['target']); return send(chat, t, kb)
    if st['t'] == 'find':
        raw = parse_address(text)
        if raw: t, kb = adm_wallet(raw); return send(chat, t, kb)
        r = find_user(text)
        if not r: return send(chat, 'Не нашёл. Пришли @логин, id или адрес', [[B('🔎 Ещё раз', 'ad:find'), B('‹ Админка', 'ad:home')]])
        t, kb = adm_card(r[0]); return send(chat, t, kb)

def admin_command(chat, u, text):
    cmd, _, arg = text.partition(' ')
    if cmd == '/broadcast':
        pending[chat] = {'t': 'bc'}; return send(chat, 'Пришли текст рассылки одним сообщением', [[B('Отмена', 'ad:home')]])
    if cmd in ('/ban', '/unban', '/user'):
        who_, _, reason = arg.strip().partition(' ')
        r = find_user(who_)
        if not r: return send(chat, 'Не нашёл. Нужен @логин или id')
        if cmd == '/ban': do_ban(chat, r[0], reason.strip())
        elif cmd == '/unban': do_unban(r[0])
        t, kb = adm_card(r[0]); return send(chat, t, kb)
    if cmd in ('/banaddr', '/unbanaddr'):
        a, _, reason = arg.strip().partition(' ')
        raw = parse_address(a)
        if not raw: return send(chat, 'Неверный адрес')
        db.run('DELETE FROM banned_addrs WHERE raw=?', (raw,))
        if cmd == '/banaddr':
            db.run('INSERT INTO banned_addrs (raw, reason, at) VALUES (?,?,?)', (raw, reason.strip(), now()))
            return send(chat, f'🚫 Адрес заблокирован в кошельке\n<code>{friendly(raw)}</code>')
        return send(chat, f'✅ Адрес разблокирован\n<code>{friendly(raw)}</code>')

def do_broadcast(admin_chat, text, btn):
    ids = [r[0] for r in db.run('SELECT tg_id FROM users WHERE banned=0', fetch=True)]
    ok = 0
    for i in ids:
        if send(i, H(text), [[WALLET]] if btn else None).get('ok'): ok += 1
        time.sleep(0.05)
    send(admin_chat, f'📣 Рассылка завершена: доставлено {ok} из {len(ids)}', [[B('‹ Админка', 'ad:home')]])

# ================================================================ наблюдение за кошельками
def is_banned_raw(raw):
    if db.one('SELECT raw FROM banned_addrs WHERE raw=?', (raw,)): return True
    return bool(db.one('SELECT a.raw FROM addrs a JOIN users u ON u.tg_id=a.tg_id WHERE a.raw=? AND u.banned=1', (raw,)))

def notification_text(item, raw):
    head = ('⚠️ <b>Похоже на скам</b> — не переходи по ссылкам из комментария\n' if item['scam'] else '')
    return (head + f'💎 <b>+{fmt(item["amount"])} {H(item["sym"])}</b> {usd(item["usd"])}\n'
            f'от {H(short(item["from"]))}\n' + (f'💬 «{H(item["comment"][:200])}»\n' if item['comment'] else '') +
            f'\nКошелёк: <code>{short(friendly(raw))}</code>')

def check_address(raw):
    rows = db.run('SELECT a.tg_id, a.last_lt, u.notify, u.scam_alerts, u.min_ton FROM addrs a JOIN users u ON u.tg_id=a.tg_id '
                  'WHERE a.raw=? AND u.banned=0', (raw,), fetch=True)
    if not rows: return 0
    since = min(r[1] for r in rows)
    evs = tonapi(f'/v2/accounts/{raw}/events?limit=20').get('events', [])
    new = sorted([e for e in evs if int(e['lt']) > since and not e.get('in_progress')], key=lambda e: int(e['lt']))
    sent = 0
    for e in new:
        for item in incoming_from_event(e, raw):
            kb = [[WALLET], [{'text': '🔍 Транзакция', 'url': f'https://tonviewer.com/transaction/{e["event_id"]}'}]]
            for tg_id, last, notify, scam_ok, min_ton in rows:
                if int(e['lt']) <= last or not notify: continue
                if item['scam'] and not scam_ok: continue
                if item['ton'] and item['amount'] < float(min_ton or 0): continue
                if send(tg_id, notification_text(item, raw), kb).get('ok'): sent += 1
    if new:
        top = max(int(e['lt']) for e in new)
        db.run('UPDATE addrs SET last_lt=? WHERE raw=? AND last_lt<?', (top, raw, top))
    if sent: bump_notifications(sent)
    return sent

def watcher():
    while True:
        try:
            for (raw,) in db.run('SELECT DISTINCT a.raw FROM addrs a JOIN users u ON u.tg_id=a.tg_id WHERE u.banned=0', fetch=True):
                try: check_address(raw)
                except Exception as e: log('watch error', short(raw), e)
        except Exception as e: log('watcher loop error', e)
        time.sleep(15)

def keepalive():
    while PUBLIC_URL:
        time.sleep(600)
        try: requests.get(PUBLIC_URL + '/health', timeout=20)
        except Exception: pass

# ================================================================ HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        origin = self.headers.get('Origin', '')
        if origin in ALLOWED_ORIGINS: self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/health': return self._json(200, {'ok': True, 'token': bool(TOKEN), 'db': 'postgres' if db.pg else 'sqlite'})
        if u.path == '/api/check':
            raw = parse_address((parse_qs(u.query).get('a') or [''])[0])
            if not raw: return self._json(400, {'error': 'bad address'})
            return self._json(200, {'banned': is_banned_raw(raw)})
        self._json(404, {'error': 'not found'})
    def do_POST(self):
        if self.path == '/api/check':
            # кошелёк отмечается при открытии: {a, net, ver, src, init}; body text/plain, чтобы обойтись без preflight
            n = min(int(self.headers.get('Content-Length', '0')), 8192)
            try: d = json.loads(self.rfile.read(n) or b'{}')
            except Exception: d = {}
            raw = parse_address(str(d.get('a', '')))
            if not raw: return self._json(400, {'error': 'bad address'})
            net = 'testnet' if d.get('net') == 'testnet' else 'mainnet'
            try: wallet_seen(raw, net, str(d.get('ver', ''))[:8], str(d.get('src', 'web'))[:8], tg_user_from_init(str(d.get('init', ''))[:4096]))
            except Exception as e: log('wallet_seen error', repr(e))
            return self._json(200, {'banned': is_banned_raw(raw)})
        if not TOKEN or self.path != f'/tg/{WEBHOOK_SECRET}' or self.headers.get('X-Telegram-Bot-Api-Secret-Token') != WEBHOOK_SECRET:
            return self._json(403, {'error': 'forbidden'})
        n = int(self.headers.get('Content-Length', '0'))
        try: upd = json.loads(self.rfile.read(n) or b'{}')
        except Exception: upd = {}
        self._json(200, {'ok': True})
        try:
            if 'message' in upd: on_message(upd['message'])
            elif 'callback_query' in upd: on_callback(upd['callback_query'])
        except Exception as e: log('update error', repr(e))

def setup_telegram():
    r = tg('setWebhook', url=f'{PUBLIC_URL}/tg/{WEBHOOK_SECRET}', secret_token=WEBHOOK_SECRET, allowed_updates=['message', 'callback_query'])
    log('webhook:', r.get('ok'), r.get('description', ''))
    tg('setChatMenuButton', menu_button={'type': 'web_app', 'text': 'Кошелёк', 'web_app': {'url': WALLET_URL}})
    tg('setMyCommands', commands=[{'command': 'start', 'description': 'Меню'}, {'command': 'balance', 'description': 'Баланс'},
                                  {'command': 'list', 'description': 'Мои адреса'}, {'command': 'help', 'description': 'Помощь'}])
    tg('setMyShortDescription', short_description='TON-кошелёк и уведомления о поступлениях')

def main():
    global db
    db = DB()
    log('db:', 'postgres' if db.pg else 'sqlite (временная, задай DATABASE_URL)', '| admins:', ', '.join(ADMINS) or '—')
    if TOKEN and PUBLIC_URL and not DRY_RUN: setup_telegram()
    elif not TOKEN: log('TELEGRAM_BOT_TOKEN не задан: бот ждёт токен (задай его в настройках Render)')
    if TOKEN: threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=keepalive, daemon=True).start()
    log('http on', PORT)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

if __name__ == '__main__':
    main()
