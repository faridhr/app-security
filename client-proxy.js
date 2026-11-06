const http = require('http');
const https = require('https');
const { URL } = require('url');
const { Transform } = require('stream');

// ================= KONFIGURASI CLIENT =================
const DEBUG_MODE = true; // Set ke false untuk mematikan log payload di terminal
const LISTEN_PORT = 3000; // Port lokal untuk diset di AI Client (Base URL: http://127.0.0.1:3000/v1)
const TARGET_BASE_URL = 'https://target-nginx-kamu.com'; // URL server Nginx tujuan
const CUSTOM_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
const SECRET_KEY = Buffer.from('KunciRahasia123!@#'); // Wajib sama persis dengan di server

// Mapping URL ke path kamuflase Nginx (path asli tetap disimpan & dipulihkan otomatis di server)
const PATH_MAPPING = {
	'/v1/chat/completions': '/health-check',
	'/v1/message/completion': '/health-check',
	'/v1/messages': '/health-check',
	'/v1/completions': '/health-check',
	'/v1/models': '/health-check',
};
// ======================================================

function createXorStream(keyBuffer, mode, debugLabel = '') {
	let offset = 0;
	let isFirstChunk = true;
	let loggedBytes = 0;
	const MAX_DEBUG_BYTES = 4096; // Batas cetak log request (4KB) agar console tidak freeze saat upload image Base64

	return new Transform({
		transform(chunk, encoding, callback) {
			const out = Buffer.allocUnsafe(chunk.length);
			for (let i = 0; i < chunk.length; i++) {
				out[i] = chunk[i] ^ keyBuffer[offset % keyBuffer.length];
				offset++;
			}

			if (DEBUG_MODE) {
				if (isFirstChunk) {
					console.log(`\n┌─── [DEBUG ${debugLabel}] ───────────────────────────`);
					isFirstChunk = false;
				}

				const isRequest = debugLabel.startsWith('REQUEST');
				if (!isRequest || loggedBytes < MAX_DEBUG_BYTES) {
					const plainBuffer = mode === 'encrypt' ? chunk : out;
					const sliceToPrint = isRequest ? plainBuffer.subarray(0, MAX_DEBUG_BYTES - loggedBytes) : plainBuffer;

					process.stdout.write(sliceToPrint.toString('utf8'));
					loggedBytes += chunk.length;

					if (isRequest && loggedBytes >= MAX_DEBUG_BYTES) {
						process.stdout.write(`\n... [PAYLOAD TRUNCATED DI CONSOLE (${chunk.length} bytes chunk) - STREAM TETAP BERJALAN PENUH] ...`);
					}
				}
			}

			callback(null, out);
		},
		flush(callback) {
			if (DEBUG_MODE && !isFirstChunk) {
				console.log(`\n└─── [END ${debugLabel}] ─────────────────────────────\n`);
			}
			callback();
		},
	});
}

function xorToHex(text, keyBuffer) {
	const buf = Buffer.from(text, 'utf8');
	const out = Buffer.allocUnsafe(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ keyBuffer[i % keyBuffer.length];
	}
	return out.toString('hex');
}

function hexToXor(hexStr, keyBuffer) {
	const buf = Buffer.from(hexStr, 'hex');
	const out = Buffer.allocUnsafe(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ keyBuffer[i % keyBuffer.length];
	}
	return out.toString('utf8');
}

const server = http.createServer((clientReq, clientRes) => {
	// 1. Handle Preflight CORS
	if (clientReq.method === 'OPTIONS') {
		clientRes.writeHead(204, {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
			'Access-Control-Allow-Headers': '*',
			'Access-Control-Max-Age': '86400',
		});
		return clientRes.end();
	}

	const parsedTarget = new URL(TARGET_BASE_URL);
	const [originalPath, queryString] = clientReq.url.split('?');
	const newPath = PATH_MAPPING[originalPath] || '/health-check';

	const headers = { ...clientReq.headers };
	headers['host'] = parsedTarget.host;
	headers['user-agent'] = CUSTOM_USER_AGENT;

	// 2. Enkripsi URL asli & Query String ke dalam header x-telemetry-id
	const fullOriginalUrl = queryString ? `${originalPath}?${queryString}` : originalPath;
	headers['x-telemetry-id'] = xorToHex(fullOriginalUrl, SECRET_KEY);

	// 3. Bungkus semua header sensitif AI (Auth, API Key, Anthropic/OpenAI headers) ke dalam 1 header terenkripsi
	const hiddenHeaders = {};
	for (const key of Object.keys(headers)) {
		const lowerKey = key.toLowerCase();
		if (lowerKey === 'authorization' || lowerKey === 'x-api-key' || lowerKey.startsWith('anthropic-') || lowerKey.startsWith('openai-')) {
			hiddenHeaders[lowerKey] = headers[key];
			delete headers[key];
		}
	}
	if (Object.keys(hiddenHeaders).length > 0) {
		headers['x-session-token'] = xorToHex(JSON.stringify(hiddenHeaders), SECRET_KEY);
	}

	// 4. Samarkan Content-Type asli menjadi binary stream (application/octet-stream)
	if (headers['content-type']) {
		headers['x-meta-type'] = xorToHex(headers['content-type'], SECRET_KEY);
		headers['content-type'] = 'application/octet-stream';
	}

	// Matikan kompresi gzip agar stream byte bisa langsung di-XOR
	delete headers['accept-encoding'];

	const isHttps = parsedTarget.protocol === 'https:';
	const requestLib = isHttps ? https : http;

	const options = {
		hostname: parsedTarget.hostname,
		port: parsedTarget.port || (isHttps ? 443 : 80),
		path: newPath,
		method: clientReq.method,
		headers: headers,
		rejectUnauthorized: false, // Bypass SSL self-signed / CRL check
	};

	console.log(`[CLIENT PROXY] ${clientReq.method} ${fullOriginalUrl} ---> ${newPath}`);

	const proxyReq = requestLib.request(options, (proxyRes) => {
		const resHeaders = { ...proxyRes.headers };
		resHeaders['access-control-allow-origin'] = '*';

		// Kembalikan Content-Type asli dari server (misal: text/event-stream atau application/json)
		if (resHeaders['x-meta-type']) {
			resHeaders['content-type'] = hexToXor(resHeaders['x-meta-type'], SECRET_KEY);
			delete resHeaders['x-meta-type'];
		}

		if (DEBUG_MODE) {
			console.log(`[CLIENT PROXY] Response Status: ${proxyRes.statusCode} | Content-Type: ${resHeaders['content-type']}`);
		}

		clientRes.writeHead(proxyRes.statusCode, resHeaders);

		// Dekripsi stream response dari server dan teruskan langsung ke AI Client
		const decryptStream = createXorStream(SECRET_KEY, 'decrypt', `RESPONSE (${originalPath})`);
		proxyRes.pipe(decryptStream).pipe(clientRes, { end: true });
	});

	proxyReq.on('error', (err) => {
		console.error(`[CLIENT ERROR] ${err.message}`);
		if (!clientRes.headersSent) {
			clientRes.writeHead(502, { 'Content-Type': 'application/json' });
			clientRes.end(
				JSON.stringify({
					error: { message: `Proxy Error: ${err.message}`, type: 'proxy_error', code: 502 },
				}),
			);
		} else {
			clientRes.end();
		}
	});

	clientReq.on('aborted', () => proxyReq.destroy());

	// Enkripsi stream request dari AI Client dan teruskan ke server Nginx
	const encryptStream = createXorStream(SECRET_KEY, 'encrypt', `REQUEST (${originalPath})`);
	clientReq.pipe(encryptStream).pipe(proxyReq, { end: true });
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
	console.log(`================================================================`);
	console.log(`🔒 Client Proxy berjalan di : http://127.0.0.1:${LISTEN_PORT}`);
	console.log(`🎯 Target Server            : ${TARGET_BASE_URL}`);
	console.log(`🐞 Debug Mode               : ${DEBUG_MODE}`);
	console.log(`================================================================`);
});
