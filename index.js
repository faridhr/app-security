#!/usr/bin/env node
/**
 * Secure OpenAI-compatible proxy (zero dependency, AES-256-GCM)
 *
 * Satu file, dua mode:
 *
 *  MODE=client  -> menerima request OpenAI-compatible (plain) dari aplikasi lokal,
 *                  membungkus method/path/header/body ke dalam stream terenkripsi,
 *                  mengirimkannya sebagai POST <OUTER_PATH> dengan User-Agent samaran.
 *                  Response terenkripsi didekripsi lalu dikembalikan apa adanya.
 *
 *  MODE=server  -> menerima POST <OUTER_PATH>, mendekripsi, meneruskan ke API AI asli,
 *                  lalu mengenkripsi response (termasuk streaming SSE) ke client.
 *
 * ENV umum:
 *   MODE        client | server                      (wajib)
 *   SECRET      kunci rahasia, SAMA di kedua sisi     (wajib, min 16 karakter)
 *               buat dengan: openssl rand -base64 32
 *   PORT        port listen                           (default 3000 / 4000)
 *   HOST        bind address                          (default 127.0.0.1)
 *   OUTER_PATH  path samaran di jaringan              (default /health-check)
 *   LOG         "false" untuk mematikan log
 *
 * ENV MODE=client:
 *   UPSTREAM_URL  URL nginx/server gateway, mis. https://domain.com
 *   USER_AGENT    user-agent samaran
 *   DEBUG         "true" => tulis request (method, path, header, body) ke console
 *                 SEBELUM dienkripsi. Header sensitif otomatis disamarkan.
 *   DEBUG_MAX_BODY  batas byte body yang ditampilkan (default 4000)
 *
 * ENV MODE=server:
 *   TARGET_URL    API AI asli, mis. https://api.openai.com
 *   TARGET_UA     (opsional) paksa user-agent ke API asli; default: UA asli dari client
 *   MAX_SKEW_MS   toleransi selisih waktu anti-replay (default 300000 = 5 menit)
 */

'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { Transform } = require('stream');
const { URL } = require('url');

// ---------------------------------------------------------------- config
const MODE = process.env.MODE;
const SECRET = process.env.SECRET || '';
const OUTER_PATH = process.env.OUTER_PATH || '/health-check';
const HOST = process.env.HOST || '127.0.0.1';
const LOG = process.env.LOG !== 'false';
const MAX_SKEW_MS = parseInt(process.env.MAX_SKEW_MS || '300000', 10);
const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function die(msg) {
	console.error('ERROR:', msg);
	process.exit(1);
}
if (MODE !== 'client' && MODE !== 'server') die('env MODE harus "client" atau "server"');
if (SECRET.length < 16) die('env SECRET wajib diisi, minimal 16 karakter (disarankan: openssl rand -base64 32)');

const KEY = crypto.scryptSync(SECRET, 'ai-secure-proxy-v1', 32);
const log = (...a) => LOG && console.log(new Date().toISOString(), ...a);

// ---------------------------------------------------------------- debug (MODE=client)
const DEBUG = process.env.DEBUG === 'true';
const DEBUG_MAX_BODY = parseInt(process.env.DEBUG_MAX_BODY || '4000', 10);
const SENSITIVE_HEADERS = new Set(['authorization', 'x-api-key', 'api-key', 'cookie', 'proxy-authorization']);

function maskHeaders(headers) {
	const out = {};
	for (const [k, v] of Object.entries(headers)) {
		const s = Array.isArray(v) ? v.join(', ') : String(v);
		out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? s.slice(0, 12) + '***' : s;
	}
	return out;
}

/** Salin body yang lewat (maks DEBUG_MAX_BODY byte) tanpa mengubah alirannya. */
class BodyTap extends Transform {
	constructor(onDone) {
		super();
		this.kept = [];
		this.keptSize = 0;
		this.total = 0;
		this.onDone = onDone;
	}
	_transform(chunk, _enc, cb) {
		this.total += chunk.length;
		if (this.keptSize < DEBUG_MAX_BODY) {
			const part = chunk.subarray(0, DEBUG_MAX_BODY - this.keptSize);
			this.kept.push(part);
			this.keptSize += part.length;
		}
		cb(null, chunk); // teruskan utuh
	}
	_flush(cb) {
		try {
			this.onDone(Buffer.concat(this.kept).toString('utf8'), this.total);
		} catch (_) {}
		cb();
	}
}

function debugRequest(meta, body, total) {
	const truncated = total > DEBUG_MAX_BODY;
	let shown = body;
	if (!truncated) {
		try {
			shown = JSON.stringify(JSON.parse(body), null, 2); // rapikan jika JSON
		} catch (_) {}
	}
	console.log(
		[
			'',
			`[DEBUG] ===== REQUEST (sebelum enkripsi) ${new Date().toISOString()} =====`,
			`${meta.method} ${meta.path}`,
			'headers: ' + JSON.stringify(maskHeaders(meta.headers), null, 2),
			`body (${total} bytes${truncated ? `, ditampilkan ${DEBUG_MAX_BODY} byte pertama` : ''}):`,
			total ? shown : '(kosong)',
			'[DEBUG] ===== END =====',
			'',
		].join('\n'),
	);
}

// ---------------------------------------------------------------- framing + AES-256-GCM
// Wire format per frame:  [4 byte len][12 byte IV][ciphertext][16 byte GCM tag]
// Plaintext frame:        [1 byte type][payload]
const T_DATA = 0;
const T_END = 1; // penanda akhir -> mendeteksi stream terpotong
const T_META = 2; // frame pertama: JSON metadata
const MAX_PLAIN = 64 * 1024; // pecah chunk besar
const MAX_FRAME = 4 * 1024 * 1024; // batas keamanan ukuran frame

function sealFrame(type, payload) {
	const iv = crypto.randomBytes(12);
	const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
	const ct = Buffer.concat([c.update(Buffer.concat([Buffer.from([type]), payload])), c.final()]);
	const tag = c.getAuthTag();
	const body = Buffer.concat([iv, ct, tag]);
	const len = Buffer.alloc(4);
	len.writeUInt32BE(body.length);
	return Buffer.concat([len, body]);
}

function openFrame(body) {
	if (body.length < 12 + 16 + 1) throw new Error('frame too short');
	const iv = body.subarray(0, 12);
	const tag = body.subarray(body.length - 16);
	const ct = body.subarray(12, body.length - 16);
	const d = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
	d.setAuthTag(tag);
	const pt = Buffer.concat([d.update(ct), d.final()]); // throw jika data dimanipulasi / kunci salah
	return { type: pt[0], payload: pt.subarray(1) };
}

/** plaintext bytes -> encrypted frames. Frame pertama = META. */
class Encryptor extends Transform {
	constructor(meta) {
		super();
		this.push(sealFrame(T_META, Buffer.from(JSON.stringify(meta))));
	}
	_transform(chunk, _enc, cb) {
		for (let i = 0; i < chunk.length; i += MAX_PLAIN) {
			this.push(sealFrame(T_DATA, chunk.subarray(i, i + MAX_PLAIN)));
		}
		cb();
	}
	_flush(cb) {
		this.push(sealFrame(T_END, Buffer.alloc(0)));
		cb();
	}
}

/** encrypted frames -> plaintext bytes. Emit event 'meta' saat frame META diterima. */
class Decryptor extends Transform {
	constructor() {
		super();
		this.buf = Buffer.alloc(0);
		this.gotMeta = false;
		this.ended = false;
	}
	_transform(chunk, _enc, cb) {
		try {
			this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
			while (this.buf.length >= 4) {
				const len = this.buf.readUInt32BE(0);
				if (len > MAX_FRAME) throw new Error('frame too large');
				if (this.buf.length < 4 + len) break;
				const frame = openFrame(this.buf.subarray(4, 4 + len));
				this.buf = this.buf.subarray(4 + len);

				if (this.ended) throw new Error('data after end');
				if (frame.type === T_META) {
					if (this.gotMeta) throw new Error('duplicate meta');
					this.gotMeta = true;
					this.emit('meta', JSON.parse(frame.payload.toString('utf8')));
				} else if (!this.gotMeta) {
					throw new Error('meta missing');
				} else if (frame.type === T_DATA) {
					this.push(frame.payload);
				} else if (frame.type === T_END) {
					this.ended = true;
				} else {
					throw new Error('unknown frame');
				}
			}
			cb();
		} catch (e) {
			cb(e);
		}
	}
	_flush(cb) {
		cb(this.ended && !this.buf.length ? null : new Error('stream truncated'));
	}
}

// ---------------------------------------------------------------- shared helpers
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

function pickHeaders(src, extraDrop = []) {
	const drop = new Set(extraDrop);
	const out = {};
	for (const [k, v] of Object.entries(src)) {
		const key = k.toLowerCase();
		if (HOP_BY_HOP.has(key) || drop.has(key)) continue;
		out[key] = v;
	}
	return out;
}

function parseBase(url) {
	const u = new URL(url);
	const secure = u.protocol === 'https:';
	const lib = secure ? https : http;
	return {
		u,
		secure,
		lib,
		basePath: u.pathname.replace(/\/+$/, ''),
		agent: new lib.Agent({ keepAlive: true, maxSockets: 256 }),
	};
}

function relax(server) {
	server.requestTimeout = 0;
	server.timeout = 0;
	server.headersTimeout = 65_000;
	server.keepAliveTimeout = 75_000;
}

function jsonError(message, code) {
	return JSON.stringify({ error: { message, type: 'proxy_error', code } });
}

// ================================================================= MODE: CLIENT
function runClient() {
	const PORT = parseInt(process.env.PORT || '3000', 10);
	const UA = process.env.USER_AGENT || DEFAULT_UA;
	if (!process.env.UPSTREAM_URL) die('MODE=client membutuhkan env UPSTREAM_URL');
	const up = parseBase(process.env.UPSTREAM_URL);

	const server = http.createServer((cReq, cRes) => {
		const t0 = Date.now();

		// Semua info asli (method, path, header termasuk Authorization) masuk ke envelope terenkripsi
		const meta = {
			ts: Date.now(),
			method: cReq.method,
			path: cReq.url,
			headers: pickHeaders(cReq.headers, ['host']),
		};

		const enc = new Encryptor(meta);
		const pReq = up.lib.request(
			{
				hostname: up.u.hostname,
				port: up.u.port || (up.secure ? 443 : 80),
				method: 'POST',
				path: up.basePath + OUTER_PATH,
				agent: up.agent,
				servername: up.secure ? up.u.hostname : undefined,
				headers: {
					host: up.u.host,
					'user-agent': UA,
					'content-type': 'application/octet-stream',
					accept: 'application/octet-stream',
				},
			},
			(pRes) => {
				if (pRes.statusCode !== 200) {
					pRes.resume();
					if (!cRes.headersSent) {
						cRes.writeHead(502, { 'content-type': 'application/json' });
						cRes.end(jsonError(`Gateway returned HTTP ${pRes.statusCode}`, 'bad_gateway'));
					}
					return;
				}
				const dec = new Decryptor();
				dec.once('meta', (m) => {
					const h = pickHeaders(m.headers || {}, ['content-length']);
					cRes.writeHead(m.status || 502, h);
					if (cRes.flushHeaders) cRes.flushHeaders();
				});
				dec.on('error', (e) => {
					log('decrypt error:', e.message);
					if (!cRes.headersSent) {
						cRes.writeHead(502, { 'content-type': 'application/json' });
						cRes.end(jsonError('Decrypt failed: ' + e.message, 'decrypt_error'));
					} else cRes.destroy(e);
				});
				pRes.on('error', (e) => dec.destroy(e));
				pRes.pipe(dec).pipe(cRes);
				cRes.on('finish', () => log(`${cReq.method} ${cReq.url} [${cRes.statusCode}] ${Date.now() - t0}ms`));
			},
		);

		pReq.setTimeout(0);
		pReq.on('error', (e) => {
			log('gateway error:', e.message);
			if (!cRes.headersSent) {
				cRes.writeHead(502, { 'content-type': 'application/json' });
				cRes.end(jsonError('Bad gateway: ' + e.message, 'bad_gateway'));
			} else cRes.destroy(e);
		});
		cRes.on('close', () => {
			if (!cRes.writableEnded) pReq.destroy();
		});
		cReq.on('error', () => pReq.destroy());

		// DEBUG: tampilkan request asli (plaintext) sebelum masuk ke Encryptor
		let source = cReq;
		if (DEBUG) {
			source = cReq.pipe(new BodyTap((body, total) => debugRequest(meta, body, total)));
			source.on('error', () => pReq.destroy());
		}
		source.pipe(enc).pipe(pReq);
	});

	relax(server);
	if (DEBUG) console.log('[client] DEBUG=true: request plaintext akan ditulis ke console');
	server.listen(PORT, HOST, () => {
		console.log(`[client] listen http://${HOST}:${PORT}  ->  ${process.env.UPSTREAM_URL}${OUTER_PATH}`);
	});
	return server;
}

// ================================================================= MODE: SERVER
function runServer() {
	const PORT = parseInt(process.env.PORT || '4000', 10);
	if (!process.env.TARGET_URL) die('MODE=server membutuhkan env TARGET_URL');
	const tgt = parseBase(process.env.TARGET_URL);
	const TARGET_UA = process.env.TARGET_UA || '';

	const server = http.createServer((req, res) => {
		const t0 = Date.now();
		const pathname = new URL(req.url, 'http://x').pathname;

		// Selain POST ke OUTER_PATH -> tampil seperti health-check biasa
		if (pathname !== OUTER_PATH) {
			res.writeHead(404, { 'content-type': 'text/plain' });
			return res.end('Not Found');
		}
		if (req.method !== 'POST') {
			res.writeHead(200, { 'content-type': 'application/json' });
			return res.end('{"status":"ok"}');
		}

		const dec = new Decryptor();
		let upstreamReq = null;
		let responded = false;

		// Kirim response terenkripsi (dipakai untuk error juga)
		const startEncrypted = (status, headers) => {
			responded = true;
			res.writeHead(200, {
				'content-type': 'application/octet-stream',
				'cache-control': 'no-cache',
				'x-accel-buffering': 'no',
			});
			if (res.flushHeaders) res.flushHeaders();
			const enc = new Encryptor({ ts: Date.now(), status, headers });
			enc.on('error', () => res.destroy());
			enc.pipe(res);
			return enc;
		};
		const sendError = (status, msg, code) => {
			if (responded) return res.destroy();
			const enc = startEncrypted(status, { 'content-type': 'application/json' });
			enc.end(Buffer.from(jsonError(msg, code)));
		};

		dec.once('meta', (m) => {
			if (!m || typeof m.path !== 'string' || typeof m.method !== 'string' || typeof m.ts !== 'number') {
				return dec.destroy(new Error('bad meta'));
			}
			if (Math.abs(Date.now() - m.ts) > MAX_SKEW_MS) {
				return dec.destroy(new Error('timestamp out of range (replay / clock skew)'));
			}
			if (!m.path.startsWith('/')) return dec.destroy(new Error('bad path'));

			const headers = pickHeaders(m.headers || {}, ['host']);
			headers.host = tgt.u.host;
			if (TARGET_UA) headers['user-agent'] = TARGET_UA;

			upstreamReq = tgt.lib.request(
				{
					hostname: tgt.u.hostname,
					port: tgt.u.port || (tgt.secure ? 443 : 80),
					method: m.method,
					path: tgt.basePath + m.path,
					headers,
					agent: tgt.agent,
					servername: tgt.secure ? tgt.u.hostname : undefined,
				},
				(pRes) => {
					const enc = startEncrypted(pRes.statusCode || 502, pickHeaders(pRes.headers));
					pRes.on('error', (e) => enc.destroy(e));
					pRes.pipe(enc);
					pRes.on('end', () => log(`${m.method} ${m.path} [${pRes.statusCode}] ${Date.now() - t0}ms`));
				},
			);
			upstreamReq.setTimeout(0);
			upstreamReq.on('error', (e) => {
				log('target error:', e.message);
				sendError(502, 'Bad gateway: ' + e.message, 'bad_gateway');
			});
			dec.pipe(upstreamReq);
		});

		dec.on('error', (e) => {
			log('decrypt error:', e.message);
			if (upstreamReq) upstreamReq.destroy();
			if (!responded) {
				responded = true;
				res.writeHead(400, { 'content-type': 'text/plain' });
				res.end('Bad Request');
			} else res.destroy();
		});

		res.on('close', () => {
			if (!res.writableEnded && upstreamReq) upstreamReq.destroy();
		});
		req.on('error', () => dec.destroy());
		req.pipe(dec);
	});

	relax(server);
	server.listen(PORT, HOST, () => {
		console.log(`[server] listen http://${HOST}:${PORT}${OUTER_PATH}  ->  ${process.env.TARGET_URL}`);
	});
	return server;
}

// ---------------------------------------------------------------- bootstrap
const srv = MODE === 'client' ? runClient() : runServer();
for (const sig of ['SIGINT', 'SIGTERM']) {
	process.on(sig, () => {
		srv.close(() => process.exit(0));
		setTimeout(() => process.exit(0), 5000).unref();
	});
}
