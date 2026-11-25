"""Starlify bot: уведомления о поступлениях на TON-кошельки + админка.

Переменные окружения:
  TELEGRAM_BOT_TOKEN  — токен из @BotFather (обязательно, задаётся в Render вручную)
  DATABASE_URL        — Postgres (на Render); без неё используется локальный SQLite
  ADMIN_USERNAMES     — логины админов через запятую, без @ (например: vexelele)
  WALLET_URL          — адрес кошелька Starlify для кнопки «Открыть кошелёк»
  TONAPI_KEY          — необязательно: ключ TonAPI, снимает лимит 1 запрос/сек
  RENDER_EXTERNAL_URL — подставляет Render; нужен для вебхука Telegram
"""
import base64, hashlib, html, json, os, sqlite3, sys, threading, time
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
DRY_RUN = os.environ.get('DRY_RUN') == '1'          # локальная проверка: сообщения печатаются, а не отправляются
WEBHOOK_SECRET = hashlib.sha256(('starlify:' + TOKEN).encode()).hexdigest()[:32] if TOKEN else ''
ALLOWED_ORIGINS = {'https://vexelele-wallet.onrender.com', 'http://localhost:5173', 'http://127.0.0.1:5173'}
MAX_ADDRS = 5

def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)

# ---------------------------------------------------------------- база данных
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

    def run(self, sql, args=(), fetch=False):
        if self.pg: sql = sql.replace('?', '%s')
        with self.lock:
            cur = self.conn.cursor(); cur.execute(sql, args)
            rows = cur.fetchall() if fetch else None
            if not self.pg: self.conn.commit()
            cur.close()
            return rows

    def one(self, sql, args=()):
        r = self.run(sql, args, fetch=True); return r[0] if r else None

db = None

# ---------------------------------------------------------------- адреса TON
def _crc16(data: bytes) -> bytes:
    reg = 0
    for b in data:
        reg ^= b << 8
        for _ in range(8):
            reg = ((reg << 1) ^ 0x1021) if reg & 0x8000 else (reg << 1)
            reg &= 0xFFFF
    return reg.to_bytes(2, 'big')

def parse_address(s: str):
    """'UQ…'/'EQ…'/'0:hex' -> '0:hex' (raw) или None"""
    s = (s or '').strip()
    if ':' in s:
        wc, _, h = s.partition(':')
        if wc in ('0', '-1') and len(h) == 64 and all(c in '0123456789abcdefABCDEF' for c in h):
            return f'{wc}:{h.lower()}'
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

def short(addr: str) -> str:
    return addr[:6] + '…' + addr[-6:] if len(addr) > 14 else addr

# ---------------------------------------------------------------- TonAPI
_last_call = 0.0
def tonapi(path):
    global _last_call
    headers = {'Authorization': f'Bearer {TONAPI_KEY}'} if TONAPI_KEY else {}
    for attempt in range(4):
        wait = (0.15 if TONAPI_KEY else 1.1) - (time.time() - _last_call)
        if wait > 0: time.sleep(wait)
        _last_call = time.time()
        r = requests.get('https://tonapi.io' + path, headers=headers, timeout=20)
        if r.status_code == 429: time.sleep(1.5 * (attempt + 1)); continue
        r.raise_for_status(); return r.json()
    raise RuntimeError('tonapi rate limit')

def fmt_amount(v: float) -> str:
    a = abs(v)
    d = 4 if a >= 1 else 6 if a >= 0.0001 else 9
    s = f'{v:,.{d}f}'.rstrip('0').rstrip('.').replace(',', ' ').replace('.', ',')
    return s

def incoming_from_event(ev, raw):
    """События, где адрес что-то получил -> список уведомлений"""
    out = []
    for a in ev.get('actions', []):
        if a.get('status') != 'ok': continue
        t = a.get('TonTransfer') or a.get('JettonTransfer')
        if not t: continue
        if (t.get('recipient') or {}).get('address', '').lower() != raw: continue
        if a.get('TonTransfer'):
            amount, sym = int(t['amount']) / 1e9, 'TON'
        else:
            j = t.get('jetton') or {}
            amount, sym = int(t['amount']) / 10 ** int(j.get('decimals', 9)), j.get('symbol') or 'токенов'
        sender = t.get('sender') or {}
        out.append({'amount': amount, 'sym': sym, 'from': sender.get('name') or (friendly(sender['address']) if sender.get('address') else '—'),
                    'comment': t.get('comment') or '', 'scam': bool(ev.get('is_scam') or sender.get('is_scam'))})
    return out

def latest_lt(raw):
    evs = tonapi(f'/v2/accounts/{raw}/events?limit=1').get('events', [])
    return int(evs[0]['lt']) if evs else 0

# ---------------------------------------------------------------- Telegram
def tg(method, **params):
    if DRY_RUN:
        log('[DRY]', method, json.dumps(params, ensure_ascii=False)[:400]); return {'ok': True, 'result': {}}
    r = requests.post(f'https://api.telegram.org/bot{TOKEN}/{method}', json=params, timeout=20)
    data = r.json()
    if not data.get('ok'): log('tg error', method, data.get('description'))
    return data

def send(chat, text, kb=None):
    p = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
    if kb: p['reply_markup'] = {'inline_keyboard': kb}
    return tg('sendMessage', **p)

# Mini App: кошелёк открывается прямо внутри Telegram
WALLET_BTN = [[{'text': 'Открыть Starlify Wallet', 'web_app': {'url': WALLET_URL}}]]
H = html.escape

def is_admin(u): return (u.get('username') or '').lower() in ADMINS

# ---------------------------------------------------------------- пользователи
def touch_user(u):
    now = int(time.time())
    if db.one('SELECT tg_id FROM users WHERE tg_id=?', (u['id'],)):
        db.run('UPDATE users SET username=?, first_name=?, last_seen=? WHERE tg_id=?', (u.get('username'), u.get('first_name'), now, u['id']))
    else:
        db.run('INSERT INTO users (tg_id, username, first_name, joined, last_seen, banned) VALUES (?,?,?,?,?,0)',
               (u['id'], u.get('username'), u.get('first_name'), now, now))
    return db.one('SELECT banned, ban_reason FROM users WHERE tg_id=?', (u['id'],))

def find_user(token):
    token = token.strip().lstrip('@')
    if token.isdigit(): return db.one('SELECT tg_id, username, first_name, banned FROM users WHERE tg_id=?', (int(token),))
    return db.one('SELECT tg_id, username, first_name, banned FROM users WHERE lower(username)=?', (token.lower(),))

def user_addrs(tg_id):
    return [r[0] for r in db.run('SELECT raw FROM addrs WHERE tg_id=? ORDER BY id', (tg_id,), fetch=True)]

HELP = ('<b>Starlify</b> — уведомления о поступлениях на твой TON-кошелёк.\n\n'
        'Пришли адрес кошелька (UQ… или EQ…), и я буду писать, когда на него придут TON, USDT или другие токены.\n\n'
        '/list — мои адреса\n/unlink 1 — отвязать адрес №1\n/help — помощь')

def on_message(m):
    u = m.get('from') or {}
    chat = m['chat']['id']
    if m['chat'].get('type') != 'private': return
    banned = touch_user(u)
    text = (m.get('text') or '').strip()
    admin = is_admin(u)
    if banned and banned[0] and not admin:
        send(chat, 'Доступ к боту ограничен.' + (f'\nПричина: {H(banned[1])}' if banned[1] else '')); return
    if admin and handle_admin(chat, u, text): return
    if text.startswith('/start') or text == '/help':
        send(chat, HELP, WALLET_BTN); return
    if text == '/list':
        a = user_addrs(u['id'])
        send(chat, '\n'.join(f'{i + 1}. <code>{friendly(r)}</code>' for i, r in enumerate(a)) if a else 'Адресов пока нет. Пришли адрес кошелька'); return
    if text.startswith('/unlink'):
        a = user_addrs(u['id']); arg = text.split(maxsplit=1)[1:] or ['']
        if arg[0].isdigit() and 1 <= int(arg[0]) <= len(a):
            db.run('DELETE FROM addrs WHERE tg_id=? AND raw=?', (u['id'], a[int(arg[0]) - 1])); send(chat, 'Адрес отвязан')
        else: send(chat, 'Напиши номер из /list, например /unlink 1')
        return
    raw = parse_address(text)
    if raw:
        if raw in user_addrs(u['id']): send(chat, 'Этот адрес уже привязан'); return
        if len(user_addrs(u['id'])) >= MAX_ADDRS: send(chat, f'Можно привязать до {MAX_ADDRS} адресов. Отвяжи лишний через /unlink'); return
        try: lt = latest_lt(raw)
        except Exception: lt = 0
        db.run('INSERT INTO addrs (tg_id, raw, last_lt) VALUES (?,?,?)', (u['id'], raw, lt))
        send(chat, f'Готово. Слежу за <code>{friendly(raw)}</code>\nНапишу, как только на него что-то придёт', WALLET_BTN); return
    send(chat, 'Не понял. Пришли адрес TON-кошелька или /help')

# ---------------------------------------------------------------- админка
pending_broadcast = {}   # admin chat -> text

def admin_menu():
    return [[{'text': '📊 Статистика', 'callback_data': 'a:stats'}, {'text': '👥 Пользователи', 'callback_data': 'a:users'}],
            [{'text': '📣 Рассылка', 'callback_data': 'a:bc'}, {'text': '🚫 Забаненные', 'callback_data': 'a:banned'}]]

ADMIN_HELP = ('<b>Админка Starlify</b>\n\n'
              '/ban @логин или id [причина] — бан в боте и в кошельке\n/unban @логин или id\n'
              '/user @логин или id — карточка пользователя\n/banaddr адрес [причина] — заблокировать адрес в кошельке\n'
              '/unbanaddr адрес\n/broadcast — рассылка всем')

def stats_text():
    n = db.one('SELECT count(*) FROM users')[0]; b = db.one('SELECT count(*) FROM users WHERE banned=1')[0]
    a = db.one('SELECT count(*) FROM addrs')[0]; ba = db.one('SELECT count(*) FROM banned_addrs')[0]
    day = db.one('SELECT count(*) FROM users WHERE last_seen>?', (int(time.time()) - 86400,))[0]
    return (f'<b>Статистика</b>\nПользователей: {n}\nАктивны за сутки: {day}\nПривязано адресов: {a}\n'
            f'Забанено пользователей: {b}\nЗаблокировано адресов: {ba}')

def user_card(r):
    tg_id, username, first_name, banned = r
    a = user_addrs(tg_id)
    return (f'<b>{H(first_name or "—")}</b> {("@" + H(username)) if username else ""}\nid: <code>{tg_id}</code>\n'
            f'Статус: {"🚫 забанен" if banned else "✅ активен"}\nАдреса:\n' + ('\n'.join(f'<code>{friendly(x)}</code>' for x in a) or '—'))

def set_ban(target, value, reason=''):
    db.run('UPDATE users SET banned=?, ban_reason=? WHERE tg_id=?', (1 if value else 0, reason if value else None, target))

def handle_admin(chat, u, text):
    if chat in pending_broadcast and text and not text.startswith('/'):
        pending_broadcast[chat] = text
        n = db.one('SELECT count(*) FROM users WHERE banned=0')[0]
        send(chat, f'<b>Предпросмотр рассылки</b> ({n} получателей):\n\n{H(text)}',
             [[{'text': '✅ Отправить всем', 'callback_data': 'a:bc_go'}, {'text': 'Отмена', 'callback_data': 'a:bc_no'}]])
        return True
    cmd, _, arg = text.partition(' ')
    if cmd == '/admin': send(chat, ADMIN_HELP, admin_menu()); return True
    if cmd == '/broadcast': pending_broadcast[chat] = ''; send(chat, 'Пришли текст рассылки одним сообщением'); return True
    if cmd in ('/ban', '/unban', '/user'):
        who, _, reason = arg.strip().partition(' ')
        r = find_user(who) if who else None
        if not r: send(chat, 'Пользователь не найден. Нужен @логин или id из /user'); return True
        if cmd == '/user': send(chat, user_card(r)); return True
        set_ban(r[0], cmd == '/ban', reason.strip())
        send(chat, ('🚫 Забанен: ' if cmd == '/ban' else '✅ Разбанен: ') + H(r[2] or str(r[0])) + '\nЕго адреса ' + ('заблокированы' if cmd == '/ban' else 'разблокированы') + ' в кошельке')
        if cmd == '/ban': send(r[0], 'Доступ к боту ограничен.' + (f'\nПричина: {H(reason.strip())}' if reason.strip() else ''))
        return True
    if cmd in ('/banaddr', '/unbanaddr'):
        a, _, reason = arg.strip().partition(' ')
        raw = parse_address(a)
        if not raw: send(chat, 'Неверный адрес'); return True
        if cmd == '/banaddr':
            db.run('DELETE FROM banned_addrs WHERE raw=?', (raw,))
            db.run('INSERT INTO banned_addrs (raw, reason, at) VALUES (?,?,?)', (raw, reason.strip(), int(time.time())))
            send(chat, f'🚫 Адрес заблокирован в кошельке:\n<code>{friendly(raw)}</code>')
        else:
            db.run('DELETE FROM banned_addrs WHERE raw=?', (raw,)); send(chat, f'✅ Адрес разблокирован:\n<code>{friendly(raw)}</code>')
        return True
    return False

def on_callback(cq):
    u = cq.get('from') or {}; chat = cq['message']['chat']['id']; data = cq.get('data', '')
    tg('answerCallbackQuery', callback_query_id=cq['id'])
    if not is_admin(u): return
    if data == 'a:stats': send(chat, stats_text(), admin_menu())
    elif data == 'a:users':
        rows = db.run('SELECT tg_id, username, first_name, banned FROM users ORDER BY joined DESC LIMIT 20', fetch=True)
        send(chat, '<b>Последние 20</b>\n' + '\n'.join(f'{"🚫" if r[3] else "•"} {H(r[2] or "—")} {("@" + H(r[1])) if r[1] else ""} <code>{r[0]}</code>' for r in rows) or 'Пусто')
    elif data == 'a:banned':
        rows = db.run('SELECT tg_id, username, first_name, ban_reason FROM users WHERE banned=1 LIMIT 50', fetch=True)
        ad = db.run('SELECT raw, reason FROM banned_addrs LIMIT 50', fetch=True)
        send(chat, '<b>Забаненные</b>\n' + ('\n'.join(f'• {H(r[2] or "—")} {("@" + H(r[1])) if r[1] else ""} <code>{r[0]}</code> {H(r[3] or "")}' for r in rows) or '—')
             + '\n\n<b>Адреса</b>\n' + ('\n'.join(f'• <code>{friendly(r[0])}</code> {H(r[1] or "")}' for r in ad) or '—'))
    elif data == 'a:bc': pending_broadcast[chat] = ''; send(chat, 'Пришли текст рассылки одним сообщением')
    elif data == 'a:bc_no': pending_broadcast.pop(chat, None); send(chat, 'Рассылка отменена')
    elif data == 'a:bc_go':
        text = pending_broadcast.pop(chat, '')
        if not text: send(chat, 'Нет текста рассылки'); return
        threading.Thread(target=do_broadcast, args=(chat, text), daemon=True).start()

def do_broadcast(admin_chat, text):
    ids = [r[0] for r in db.run('SELECT tg_id FROM users WHERE banned=0', fetch=True)]
    ok = 0
    for i in ids:
        if send(i, H(text)).get('ok'): ok += 1
        time.sleep(0.05)   # лимит Telegram ~30 сообщений/сек
    send(admin_chat, f'Рассылка завершена: доставлено {ok} из {len(ids)}')

# ---------------------------------------------------------------- наблюдение за кошельками
def is_banned_raw(raw):
    if db.one('SELECT raw FROM banned_addrs WHERE raw=?', (raw,)): return True
    return bool(db.one('SELECT a.raw FROM addrs a JOIN users u ON u.tg_id=a.tg_id WHERE a.raw=? AND u.banned=1', (raw,)))

def check_address(raw):
    rows = db.run('SELECT a.tg_id, a.last_lt FROM addrs a JOIN users u ON u.tg_id=a.tg_id WHERE a.raw=? AND u.banned=0', (raw,), fetch=True)
    if not rows: return 0
    since = min(r[1] for r in rows)
    evs = tonapi(f'/v2/accounts/{raw}/events?limit=20').get('events', [])
    new = sorted([e for e in evs if int(e['lt']) > since and not e.get('in_progress')], key=lambda e: int(e['lt']))
    sent = 0
    for e in new:
        for item in incoming_from_event(e, raw):
            text = (('⚠️ <b>Возможно скам</b>\n' if item['scam'] else '') +
                    f'💎 <b>Вам начислено {fmt_amount(item["amount"])} {H(item["sym"])}</b>\n'
                    f'от {H(short(item["from"]))}\n' + (f'Комментарий: {H(item["comment"][:200])}\n' if item['comment'] else '') +
                    f'\nКошелёк: <code>{short(friendly(raw))}</code>')
            for tg_id, last in rows:
                if int(e['lt']) > last: send(tg_id, text, WALLET_BTN); sent += 1
    if new:
        top = max(int(e['lt']) for e in new)
        db.run('UPDATE addrs SET last_lt=? WHERE raw=? AND last_lt<?', (top, raw, top))
    return sent

def watcher():
    while True:
        try:
            addrs = [r[0] for r in db.run('SELECT DISTINCT a.raw FROM addrs a JOIN users u ON u.tg_id=a.tg_id WHERE u.banned=0', fetch=True)]
            for raw in addrs:
                try: check_address(raw)
                except Exception as e: log('watch error', short(raw), e)
        except Exception as e: log('watcher loop error', e)
        time.sleep(15)

def keepalive():
    # бесплатный сервер Render засыпает без входящих запросов — будим его сами
    while PUBLIC_URL:
        time.sleep(600)
        try: requests.get(PUBLIC_URL + '/health', timeout=20)
        except Exception: pass

# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        origin = self.headers.get('Origin', '')
        if origin in ALLOWED_ORIGINS: self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == '/health': return self._json(200, {'ok': True, 'token': bool(TOKEN)})
        if u.path == '/api/check':
            raw = parse_address((parse_qs(u.query).get('a') or [''])[0])
            if not raw: return self._json(400, {'error': 'bad address'})
            return self._json(200, {'banned': is_banned_raw(raw)})
        self._json(404, {'error': 'not found'})
    def do_POST(self):
        if self.path != f'/tg/{WEBHOOK_SECRET}' or self.headers.get('X-Telegram-Bot-Api-Secret-Token') != WEBHOOK_SECRET:
            return self._json(403, {'error': 'forbidden'})
        n = int(self.headers.get('Content-Length', '0'))
        try: upd = json.loads(self.rfile.read(n) or b'{}')
        except Exception: upd = {}
        self._json(200, {'ok': True})
        try:
            if 'message' in upd: on_message(upd['message'])
            elif 'callback_query' in upd: on_callback(upd['callback_query'])
        except Exception as e: log('update error', e)

def main():
    global db
    db = DB()
    log('db:', 'postgres' if db.pg else 'sqlite', '| admins:', ', '.join(ADMINS) or '—')
    if TOKEN and PUBLIC_URL and not DRY_RUN:
        r = tg('setWebhook', url=f'{PUBLIC_URL}/tg/{WEBHOOK_SECRET}', secret_token=WEBHOOK_SECRET,
               allowed_updates=['message', 'callback_query'], drop_pending_updates=False)
        log('webhook:', r.get('ok'), r.get('description', ''))
        tg('setChatMenuButton', menu_button={'type': 'web_app', 'text': 'Кошелёк', 'web_app': {'url': WALLET_URL}})
        tg('setMyCommands', commands=[{'command': 'start', 'description': 'Начать'}, {'command': 'list', 'description': 'Мои адреса'},
                                      {'command': 'help', 'description': 'Помощь'}])
    elif not TOKEN:
        log('TELEGRAM_BOT_TOKEN не задан: бот ждёт токен (задай его в настройках Render и перезапусти)')
    if TOKEN: threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=keepalive, daemon=True).start()
    log('http on', PORT)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

if __name__ == '__main__':
    main()
