export interface Env {
	ASSETS: Fetcher;
}

const SQLI_PATH = '/wtv/lab/sqli';
const LFI_PATH = '/wtv/lab/files';
const FINALIZE_PATH = '/wtv/lab/finalize';
const LFI_MOUNT = 'public/views/panels/tenant/default/';
const SQLI_EXPECTED_COLUMNS = 3;
const XSS_STAGE_FLAG = 'wtv{xss_rehydration_beats_blacklists}';
const SQLI_STAGE_FLAG = 'wtv{sqli_union_leaks_shadow_notes}';
const LFI_STAGE_FLAG = 'wtv{lfi_second_decode_walks_outside_the_mount}';
const FINAL_STAGE_FLAG = 'wtv{verify_more_assume_less_chain_the_findings}';

const ROUTES: Record<string, string> = {
	'/': '/index.html',
	'/home': '/index.html',
	'/index.html': '/index.html',
	'/work': '/work/work.html',
	'/work/': '/work/work.html',
	'/work.html': '/work/work.html',
	'/projects': '/projects/projects.html',
	'/projects/': '/projects/projects.html',
	'/projects.html': '/projects/projects.html',
	'/wtv': '/wtv/wtv.html',
	'/wtv/': '/wtv/wtv.html',
	'/wtv.html': '/wtv/wtv.html',
	'/resume': '/assets/resume/DavidPinheiro-Resume.pdf',
	'/davidpinheiro-resume.pdf': '/assets/resume/DavidPinheiro-Resume.pdf',
	'/favicon.ico': '/assets/icon/favicon.ico',
};

type AccountRow = {
	id: number;
	username: string;
	role: string;
	tenant: 'public' | 'staff';
	active: boolean;
	note: string;
};

type AuditRow = {
	id: number;
	scope: string;
	message: string;
	severity: 'low' | 'medium' | 'critical';
};

const SQLI_ACCOUNTS = [
	{
		id: 101,
		username: 'visitor',
		role: 'guest',
		tenant: 'public',
		active: true,
		note: 'Public account. Nothing interesting here.',
	},
	{
		id: 147,
		username: 'analyst',
		role: 'staff',
		tenant: 'public',
		active: true,
		note: 'Query text leaks just enough to punish assumptions.',
	},
	{
		id: 204,
		username: 'staging_bot',
		role: 'service',
		tenant: 'staff',
		active: true,
		note: 'Wrong tenant. Still not the interesting row.',
	},
	{
		id: 7331,
		username: 'archive_admin',
		role: 'admin',
		tenant: 'public',
		active: false,
		note: 'Inactive. The straight path still misses.',
	},
] satisfies AccountRow[];

const SQLI_AUDIT_NOTES = [
	{
		id: 311,
		scope: 'ops',
		message: 'Rotation complete. Nothing leaked.',
		severity: 'low',
	},
	{
		id: 9001,
		scope: 'archive',
		message: SQLI_STAGE_FLAG,
		severity: 'critical',
	},
] satisfies AuditRow[];

const VIRTUAL_FILES = new Map<string, string>([
	[
		`${LFI_MOUNT}docs/welcome.txt`,
		[
			'viewer: tenant default mount',
			'gate: docs/*.txt on pass one',
			'decode: one parse in URL, another in app',
			'collapse: only after join',
		].join('\n'),
	],
	[
		`${LFI_MOUNT}docs/changelog.txt`,
		[
			'2026-02-03: moved viewer mount deeper',
			'2026-02-07: keep docs prefix guard for compatibility',
			'2026-02-08: traversal strip remains single-pass',
		].join('\n'),
	],
	[
		`${LFI_MOUNT}logs/router.txt`,
		[
			`mount = ${LFI_MOUNT}`,
			'prefix_guard = docs/',
			'suffix_guard = .txt',
			'decoder = second pass after strip',
		].join('\n'),
	],
	[
		`${LFI_MOUNT}snippets/profile.tpl`,
		['<article class="card">', '  {{ display_name }}', '</article>'].join('\n'),
	],
	[
		'private/flags/final.txt',
		[LFI_STAGE_FLAG, 'guards only work if every stage agrees on the same bytes'].join('\n'),
	],
]);

function buildContentSecurityPolicy(path: string): string {
	const relaxedWtvPolicy = [
		"default-src 'self'",
		"script-src 'self' 'unsafe-inline'",
		"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
		"font-src 'self' https://fonts.gstatic.com",
		"img-src 'self' data:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	].join('; ');

	const strictPagePolicy = [
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' https://fonts.googleapis.com",
		"font-src 'self' https://fonts.gstatic.com",
		"img-src 'self' data:",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	].join('; ');

	return path.startsWith('/wtv') ? relaxedWtvPolicy : strictPagePolicy;
}

function applySecurityHeaders(source: Headers, path: string, protocol: string): Headers {
	const headers = new Headers(source);
	const contentType = headers.get('Content-Type') ?? '';

	headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
	headers.set('X-Content-Type-Options', 'nosniff');
	headers.set('X-Frame-Options', 'DENY');
	headers.set('X-Permitted-Cross-Domain-Policies', 'none');
	headers.set('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
	headers.set('Cross-Origin-Resource-Policy', 'same-origin');

	if (protocol === 'https:') {
		headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
	}

	if (contentType.includes('text/html')) {
		headers.set('Content-Security-Policy', buildContentSecurityPolicy(path));
	}

	return headers;
}

function hardenResponse(response: Response, path: string, protocol: string, statusOverride?: number): Response {
	return new Response(response.body, {
		status: statusOverride ?? response.status,
		statusText: response.statusText,
		headers: applySecurityHeaders(response.headers, path, protocol),
	});
}

function methodNotAllowed(allowed: string[]): Response {
	return Response.json(
		{ error: 'method_not_allowed', allowed },
		{
			status: 405,
			headers: {
				Allow: allowed.join(', '),
				'Cache-Control': 'no-store',
			},
		},
	);
}

function collapsePath(input: string): string {
	const stack: string[] = [];

	for (const segment of input.split('/')) {
		if (!segment || segment === '.') {
			continue;
		}

		if (segment === '..') {
			stack.pop();
			continue;
		}

		stack.push(segment);
	}

	return stack.join('/');
}

function safeDecode(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function normalizeSqlInput(value: string): string {
	return value.replace(/\/\*[\s\S]*?\*\//g, '').replace(/[\t\r\n]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

function splitSqlProjection(input: string): string[] {
	const parts: string[] = [];
	let current = '';
	let inQuote = false;

	for (const character of input) {
		if (character === "'") {
			inQuote = !inQuote;
			current += character;
			continue;
		}

		if (character === ',' && !inQuote) {
			parts.push(current.trim());
			current = '';
			continue;
		}

		current += character;
	}

	if (current.trim()) {
		parts.push(current.trim());
	}

	return parts;
}

function handleSqli(url: URL): Response {
	const raw = url.searchParams.get('user') ?? '';
	const normalized = normalizeSqlInput(raw);
	const rawLower = raw.toLowerCase();
	const query = `SELECT id, username, role FROM accounts WHERE username = '${raw}' AND tenant = 'public' AND active = 1 LIMIT 1;`;

	let signature = 'passed';
	if (/\bor\b/.test(rawLower) || /\bunion\b/.test(rawLower) || /\bselect\b/.test(rawLower) || /--/.test(rawLower) || /;/.test(rawLower)) {
		signature = 'blocked: raw keyword signature';
	}

	const notes = ['route = accounts', `planner = ${SQLI_EXPECTED_COLUMNS} columns`];

	let rows = SQLI_ACCOUNTS.filter(
		(account) => account.active && account.tenant === 'public' && account.username === raw,
	).map(({ id, username, role }) => ({
		id,
		username,
		role,
	}));

	let cleared = false;
	let flag: string | null = null;

	if (signature === 'passed' && normalized.includes('union')) {
		notes.push('parser = block comments collapsed before execution');

		const unionMatch = normalized.match(
			/'\s*union\s+select\s+(.+?)\s+from\s+([a-z_]+)\s+where\s+scope\s*=\s*'([^']+)'\s*(#|$)/,
		);

		if (!/#/.test(normalized)) {
			notes.push('tail = trailing query survived');
		}

		if (!unionMatch) {
			notes.push('planner = malformed union branch');
			rows = [];
		} else {
			const projection = splitSqlProjection(unionMatch[1].split('#', 1)[0].trim());
			const relation = unionMatch[2];
			const scope = unionMatch[3];

			if (projection.length !== SQLI_EXPECTED_COLUMNS) {
				notes.push(`planner = projection mismatch (${projection.length}/${SQLI_EXPECTED_COLUMNS})`);
				rows = [];
			} else if (relation !== 'audit_notes') {
				notes.push(`planner = relation "${relation}" not found`);
				rows = [];
			} else {
				const auditRow = SQLI_AUDIT_NOTES.find((row) => row.scope === scope);

				if (!auditRow) {
					notes.push(`planner = scope "${scope}" returned 0 rows`);
					rows = [];
				} else if (!/#/.test(normalized)) {
					rows = [];
				} else {
					notes.push('planner = union branch accepted');
					rows = [
						{
							id: auditRow.id,
							username: auditRow.scope,
							role: auditRow.message,
						},
					];
					cleared = auditRow.scope === 'archive';
					flag = cleared ? auditRow.message : null;
				}
			}
		}
	}

	return Response.json(
		{
			raw,
			normalized,
			query,
			signature,
			notes,
			rows,
			cleared,
			flag,
		},
		{
			headers: {
				'Cache-Control': 'no-store',
				'X-WTV-Projection': String(SQLI_EXPECTED_COLUMNS),
				'X-WTV-Route': 'sqli',
			},
		},
	);
}

function handleLfi(url: URL): Response {
	const requested = url.searchParams.get('path') ?? 'docs/welcome.txt';
	const onceDecoded = requested.replace(/\\/g, '/');
	const ticket = onceDecoded.startsWith('docs/') && onceDecoded.endsWith('.txt') ? 'granted' : 'denied';
	const stripped = onceDecoded.replace('../', '');
	const decoded = safeDecode(stripped);
	const joined = `${LFI_MOUNT}${decoded}`.replace(/\\/g, '/').replace(/\/+/g, '/');
	const resolved = collapsePath(joined);
	const content = ticket === 'granted' ? VIRTUAL_FILES.get(resolved) ?? 'ENOENT: no such file' : 'DENIED: docs/*.txt only';
	const cleared = ticket === 'granted' && resolved === 'private/flags/final.txt';

	return Response.json(
		{
			requested: onceDecoded,
			decoded,
			content,
			cleared,
			flag: cleared ? LFI_STAGE_FLAG : null,
		},
		{
			headers: {
				'Cache-Control': 'no-store',
				'X-WTV-Mount': LFI_MOUNT,
				'X-WTV-Resolved': resolved,
				'X-WTV-Ticket': ticket,
				'X-WTV-Route': 'lfi',
			},
		},
	);
}

async function handleFinalize(request: Request): Promise<Response> {
	let payload: Record<string, unknown>;

	try {
		payload = (await request.json()) as Record<string, unknown>;
	} catch {
		return Response.json(
			{ cleared: false, note: 'Send JSON with the three stage flags.' },
			{
				status: 400,
				headers: {
					'Cache-Control': 'no-store',
				},
			},
		);
	}

	const xss = String(payload.xss ?? '').trim();
	const sqli = String(payload.sqli ?? '').trim();
	const lfi = String(payload.lfi ?? '').trim();

	if (!xss || !sqli || !lfi) {
		return Response.json(
			{ cleared: false, note: 'Need all three flags.' },
			{
				status: 400,
				headers: {
					'Cache-Control': 'no-store',
				},
			},
		);
	}

	const cleared = xss === XSS_STAGE_FLAG && sqli === SQLI_STAGE_FLAG && lfi === LFI_STAGE_FLAG;

	return Response.json(
		{
			cleared,
			note: cleared ? 'Run sealed. Final flag issued.' : 'One or more flags are wrong.',
			flag: cleared ? FINAL_STAGE_FLAG : null,
		},
		{
			status: cleared ? 200 : 400,
			headers: {
				'Cache-Control': 'no-store',
			},
		},
	);
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname.toLowerCase();
		const routeTarget = ROUTES[path];

		if (path === SQLI_PATH || path === `${SQLI_PATH}/`) {
			if (request.method !== 'GET') {
				return hardenResponse(methodNotAllowed(['GET']), path, url.protocol);
			}

			return hardenResponse(handleSqli(url), path, url.protocol);
		}

		if (path === LFI_PATH || path === `${LFI_PATH}/`) {
			if (request.method !== 'GET') {
				return hardenResponse(methodNotAllowed(['GET']), path, url.protocol);
			}

			return hardenResponse(handleLfi(url), path, url.protocol);
		}

		if (path === FINALIZE_PATH || path === `${FINALIZE_PATH}/`) {
			if (request.method !== 'POST') {
				return hardenResponse(methodNotAllowed(['POST']), path, url.protocol);
			}

			return hardenResponse(await handleFinalize(request), path, url.protocol);
		}

		if (request.method !== 'GET' && request.method !== 'HEAD') {
			return hardenResponse(methodNotAllowed(['GET', 'HEAD']), path, url.protocol);
		}

		const assetRequest = routeTarget ? new Request(new URL(routeTarget, url.origin), request) : request;
		const assetResponse = await env.ASSETS.fetch(assetRequest);

		if (assetResponse.status !== 404) {
			return hardenResponse(assetResponse, path, url.protocol);
		}

		const notFoundResponse = await env.ASSETS.fetch(new Request(new URL('/404.html', url.origin), request));
		if (notFoundResponse.status !== 404) {
			return hardenResponse(notFoundResponse, path, url.protocol, 404);
		}

		return hardenResponse(
			new Response('<h1>404 Not Found</h1>', {
				status: 404,
				headers: { 'Content-Type': 'text/html; charset=UTF-8' },
			}),
			path,
			url.protocol,
		);
	},
} satisfies ExportedHandler<Env>;
