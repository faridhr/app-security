const http = require('http');
const { Transform } = require('stream');

// ================= KONFIGURASI SERVER =================
const DEBUG_MODE = true; // Set ke false untuk mematikan log payload di terminal server
const UNWRAPPER_PORT = 4000; // Port tujuan proxy_pass dari Nginx
const AI_BACKEND_HOST = '127.0.0.1';
const AI_BACKEND_PORT = 20128; // Port Backend AI (misal: 9router / LiteLLM)
const SECRET_KEY = Buffer.from('KunciRahasia123!@#'); // Wajib sama persis dengan di client
// ======================================================

function createXorStream(keyBuffer, mode, debugLabel = '') {
	let offset = 0;
	let isFirstChunk = true;
	let loggedBytes = 0;
	const MAX_DEBUG_BYTES = 4096; // Batas cetak log request (4KB) agar console server tidak penuh oleh Base64 image

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

const server = http.createServer((req, res) => {
	const headers = { ...req.headers };

	// 1. Pulihkan Path & Query String asli dari header x-telemetry-id
	let originalUrl = req.url;
	if (headers['x-telemetry-id']) {
		originalUrl = hexToXor(headers['x-telemetry-id'], SECRET_KEY);
		delete headers['x-telemetry-id'];
	}

	// 2. Pulihkan semua header sensitif AI (Authorization, x-api-key, anthropic-*, openai-*)
	if (headers['x-session-token']) {
		try {
			const restoredHeaders = JSON.parse(hexToXor(headers['x-session-token'], SECRET_KEY));
			Object.assign(headers, restoredHeaders);
		} catch (err) {
			headers['authorization'] = hexToXor(headers['x-session-token'], SECRET_KEY);
		}
		delete headers['x-session-token'];
	}

	// 3. Pulihkan Content-Type asli (misal: application/json atau multipart/form-data)
	if (headers['x-meta-type']) {
		headers['content-type'] = hexToXor(headers['x-meta-type'], SECRET_KEY);
		delete headers['x-meta-type'];
	}

	headers['host'] = `${AI_BACKEND_HOST}:${AI_BACKEND_PORT}`;
	delete headers['accept-encoding'];

	console.log(`[SERVER UNWRAP] ${req.method} ${req.url} ===> Restored to ${originalUrl}`);

	const options = {
		hostname: AI_BACKEND_HOST,
		port: AI_BACKEND_PORT,
		path: originalUrl,
		method: req.method,
		headers: headers,
	};

	const backendReq = http.request(options, (backendRes) => {
		const resHeaders = { ...backendRes.headers };

		if (DEBUG_MODE) {
			console.log(`[SERVER UNWRAP] Backend Status: ${backendRes.statusCode} | Content-Type: ${resHeaders['content-type']}`);
		}

		// Samarkan kembali Content-Type response menjadi binary stream sebelum melewati Nginx
		if (resHeaders['content-type']) {
			resHeaders['x-meta-type'] = xorToHex(resHeaders['content-type'], SECRET_KEY);
			resHeaders['content-type'] = 'application/octet-stream';
		}

		// Pastikan Nginx tidak menahan buffer SSE Streaming
		resHeaders['x-accel-buffering'] = 'no';
		resHeaders['cache-control'] = 'no-cache, no-transform';

		res.writeHead(backendRes.statusCode, resHeaders);

		// Enkripsi stream response dari Backend AI sebelum dikirim balik ke Client
		const encryptStream = createXorStream(SECRET_KEY, 'encrypt', `RESPONSE (${originalUrl})`);
		backendRes.pipe(encryptStream).pipe(res, { end: true });
	});

	backendReq.on('error', (err) => {
		console.error(`[BACKEND ERROR] ${err.message}`);
		if (!res.headersSent) {
			res.writeHead(502, { 'Content-Type': 'text/plain' });
			res.end(`Bad Gateway: ${err.message}`);
		} else {
			res.end();
		}
	});

	req.on('aborted', () => backendReq.destroy());

	// Dekripsi stream request yang masuk dari Nginx sebelum diteruskan ke Backend AI
	const decryptStream = createXorStream(SECRET_KEY, 'decrypt', `REQUEST (${originalUrl})`);
	req.pipe(decryptStream).pipe(backendReq, { end: true });
});

server.listen(UNWRAPPER_PORT, '127.0.0.1', () => {
	console.log(`================================================================`);
	console.log(`🔓 Server Unwrapper berjalan di : http://127.0.0.1:${UNWRAPPER_PORT}`);
	console.log(`🤖 AI Backend Target            : http://${AI_BACKEND_HOST}:${AI_BACKEND_PORT}`);
	console.log(`🐞 Debug Mode                   : ${DEBUG_MODE}`);
	console.log(`================================================================`);
});
