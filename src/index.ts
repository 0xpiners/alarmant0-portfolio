export interface Env {
	ASSETS: Fetcher;
}

const SQLI_PATH = '/wtv/lab/sqli';
const LFI_PATH = '/wtv/lab/files';

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

const SQLI_ACCOUNTS = [
	{
		username: 'visitor',
		role: 'guest',
		active: true,
		note: 'Public account. Nothing interesting here.',
	},
	{
		username: 'analyst',
		role: 'staff',
		active: true,
		note: 'The query string is visible for a reason.',
	},
	{
		username: 'archive_admin',
		role: 'admin',
		active: false,
		note: 'wtv{sqli_comments_defeat_the_waf}',
	},
];

const VIRTUAL_FILES = new Map<string, string>([
	[
		'public/views/panels/cards/welcome.txt',
		['wtv docs', 'root = public/views/panels/', 'decode = twice', 'strip = ../ once before second decode'].join('\n'),
	],
	[
		'public/views/panels/snippets/card.tpl',
		['<article class="card">', '  {{ user_input }}', '</article>'].join('\n'),
	],
	[
		'public/views/panels/logs/sanitizer.txt',
		['filter(script) = true', 'filter(onerror) = true', 'filter(javascript:) = true'].join('\n'),
	],
	[
		'private/flags/final.txt',
		['wtv{lfi_double_decode_slips_the_root}', 'normalization only helps if you normalized the right thing'].join('\n'),
	],
]);

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

function handleSqli(url: URL): Response {
	const raw = url.searchParams.get('user') ?? '';
	const normalized = normalizeSqlInput(raw);
	const rawLower = raw.toLowerCase();
	const query = `SELECT username, role, note FROM accounts WHERE username = '${raw}' AND active = 1 ORDER BY id DESC LIMIT 1;`;

	let waf = 'passed';
	if (/\bor\b/.test(rawLower) || /\bunion\b/.test(rawLower) || /--/.test(rawLower)) {
		waf = 'blocked: raw keyword signature';
	}

	let rows = SQLI_ACCOUNTS.filter((account) => account.active && account.username === raw).map(({ username, role, note }) => ({
		username,
		role,
		note,
	}));

	const bypassesActiveGate =
		waf === 'passed' &&
		/archive_admin/.test(normalized) &&
		/'\s*or\s*active\s*=\s*0/.test(normalized) &&
		/#/.test(normalized);

	if (bypassesActiveGate) {
		const { username, role, note } = SQLI_ACCOUNTS[2];
		rows = [{ username, role, note }];
	}

	return Response.json(
		{
			raw,
			normalized,
			query,
			waf,
			rows,
			cleared: bypassesActiveGate,
			flag: bypassesActiveGate ? SQLI_ACCOUNTS[2].note : null,
		},
		{
			headers: {
				'Cache-Control': 'no-store',
			},
		},
	);
}

function handleLfi(url: URL): Response {
	const requested = url.searchParams.get('path') ?? 'cards/welcome.txt';
	const filtered = requested.replace('../', '');
	const decoded = safeDecode(filtered);
	const joined = `public/views/panels/${decoded}`.replace(/\\/g, '/').replace(/\/+/g, '/');
	const resolved = collapsePath(joined);
	const content = VIRTUAL_FILES.get(resolved) ?? 'ENOENT: no such file';
	const cleared = resolved === 'private/flags/final.txt';

	return Response.json(
		{
			requested,
			decoded,
			resolved,
			content,
			cleared,
		},
		{
			headers: {
				'Cache-Control': 'no-store',
				'X-WTV-Resolved': resolved,
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
			return handleSqli(url);
		}

		if (path === LFI_PATH || path === `${LFI_PATH}/`) {
			return handleLfi(url);
		}

		const assetRequest = routeTarget ? new Request(new URL(routeTarget, url.origin), request) : request;
		const assetResponse = await env.ASSETS.fetch(assetRequest);

		if (assetResponse.status !== 404) {
			return assetResponse;
		}

		const notFoundResponse = await env.ASSETS.fetch(new Request(new URL('/404.html', url.origin), request));
		if (notFoundResponse.status !== 404) {
			return new Response(notFoundResponse.body, {
				status: 404,
				headers: notFoundResponse.headers,
			});
		}

		return new Response('<h1>404 Not Found</h1>', {
			status: 404,
			headers: { 'Content-Type': 'text/html; charset=UTF-8' },
		});
	},
} satisfies ExportedHandler<Env>;
