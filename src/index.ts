export interface Env {
	ASSETS: Fetcher;
}

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
	'/resume': '/assets/resume/DavidPinheiro-Resume.pdf',
	'/davidpinheiro-resume.pdf': '/assets/resume/DavidPinheiro-Resume.pdf',
	'/favicon.ico': '/assets/icon/favicon.ico',
};

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname.toLowerCase();
		const routeTarget = ROUTES[path];

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
