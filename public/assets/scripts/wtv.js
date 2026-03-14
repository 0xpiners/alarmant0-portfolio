const routes = {
	sqli: '/wtv/lab/sqli',
	lfi: '/wtv/lab/files',
};

const storageKey = 'wtv-progress-v4';
const rewardFlag = 'wtv{assumptions_are_the_real_bug}';

const stages = [
	{
		id: 'xss',
		success: 'XSS lab cleared. The preview sink executed with the review token.',
		ready: 'Sandbox armed. The preview trusts its filter more than it should.',
		locked: 'Solve the previous lab first.',
		hints: [
			'The sink is in the preview iframe, not the main page.',
			'Script tags, onerror, and javascript: are filtered. Other event paths still exist.',
		],
	},
	{
		id: 'sqli',
		success: 'SQLi lab cleared. The raw filter lost to the normalized query.',
		ready: 'Query lab armed. Watch the WAF result and the normalized string separately.',
		locked: 'Clear the XSS lab first.',
		hints: [
			'The raw filter hates obvious keywords, but the query logic runs after comment stripping.',
			'Split the keyword, then make the active check disappear behind a trailing comment.',
		],
	},
	{
		id: 'lfi',
		success: 'LFI lab cleared. Decoding and normalization disagreed about where the path really lived.',
		ready: 'File viewer armed. What gets normalized is not exactly what you typed.',
		locked: 'Clear the SQLi lab first.',
		hints: [
			'There is a traversal strip before a second decode, and the root starts deeper than it looks.',
			'If raw ../ is getting caught, think about what survives the first parse but appears after another decode.',
		],
	},
];

const state = loadState();
let currentXssToken = '';

const stageCards = Array.from(document.querySelectorAll('[data-stage-card]'));
const progressTokens = Array.from(document.querySelectorAll('[data-progress-token]'));
const logList = document.querySelector('[data-challenge-log]');
const finishPanel = document.querySelector('[data-finish]');
const rewardTarget = document.querySelector('[data-reward-flag]');
const resetButton = document.querySelector('[data-reset]');

const xssForm = document.querySelector('[data-xss-form]');
const xssInput = document.querySelector('[data-xss-input]');
const xssFrame = document.querySelector('[data-xss-frame]');
const xssLog = document.querySelector('[data-xss-log]');

const sqliForm = document.querySelector('[data-sqli-form]');
const sqliInput = document.querySelector('[data-sqli-input]');
const sqliLog = document.querySelector('[data-sqli-log]');

const lfiForm = document.querySelector('[data-lfi-form]');
const lfiInput = document.querySelector('[data-lfi-input]');
const lfiLog = document.querySelector('[data-lfi-log]');

window.addEventListener('message', handleXssMessage);

bindEvents();
render();
bootConsoles();

function bindEvents() {
	stageCards.forEach((card, index) => {
		const hintButton = card.querySelector('[data-hint-button]');

		hintButton?.addEventListener('click', () => {
			const hint = card.querySelector('[data-hint]');
			const hintIndex = Math.min(state.hints[index] ?? 0, stages[index].hints.length - 1);
			hint.textContent = stages[index].hints[hintIndex];
			hint.classList.add('is-visible');
			state.hints[index] = hintIndex + 1;
			saveState();
		});
	});

	xssForm?.addEventListener('submit', (event) => {
		event.preventDefault();

		if (state.cleared !== 0) {
			return;
		}

		const payload = xssInput?.value.trim() ?? '';
		if (!payload) {
			writeConsole(xssLog, 'Provide a payload before rendering.', true);
			return;
		}

		if (!xssFrame) {
			return;
		}

		currentXssToken = mintToken();
		xssFrame.srcdoc = buildXssPreview(payload, currentXssToken);
		writeConsole(
			xssLog,
			`Preview refreshed with ${payload.length} bytes.\nA fresh review token was minted inside the iframe.`,
			false,
		);
	});

	sqliForm?.addEventListener('submit', async (event) => {
		event.preventDefault();

		if (state.cleared !== 1) {
			return;
		}

		const user = sqliInput?.value.trim() ?? '';
		if (!user) {
			writeConsole(sqliLog, 'Enter a username probe before querying.', true);
			return;
		}

		const response = await fetch(`${routes.sqli}?user=${encodeURIComponent(user)}`, { cache: 'no-store' });
		const data = await response.json();

		writeConsole(
			sqliLog,
			[
				`waf = ${data.waf}`,
				`raw = ${data.raw}`,
				`normalized = ${data.normalized}`,
				'',
				data.query,
				'',
				`rows = ${JSON.stringify(data.rows, null, 2)}`,
				data.cleared ? `\nflag = ${data.flag}` : '',
			].join('\n'),
			data.waf !== 'passed',
		);

		if (data.cleared) {
			advanceStage(1);
		}
	});

	lfiForm?.addEventListener('submit', async (event) => {
		event.preventDefault();

		if (state.cleared !== 2) {
			return;
		}

		const path = lfiInput?.value.trim() ?? '';
		if (!path) {
			writeConsole(lfiLog, 'Enter a path before reading.', true);
			return;
		}

		const response = await fetch(`${routes.lfi}?path=${encodeURIComponent(path)}`, { cache: 'no-store' });
		const data = await response.json();

		writeConsole(
			lfiLog,
			[
				`requested = ${data.requested}`,
				`decoded = ${data.decoded}`,
				`resolved = ${data.resolved}`,
				'',
				data.content,
			].join('\n'),
			Boolean(data.error),
		);

		if (data.cleared) {
			advanceStage(2);
		}
	});

	resetButton?.addEventListener('click', () => {
		localStorage.removeItem(storageKey);
		window.location.reload();
	});

	window.wtv = Object.freeze({
		reset() {
			localStorage.removeItem(storageKey);
			window.location.reload();
		},
	});
}

function render() {
	stageCards.forEach((card, index) => {
		const isCleared = index < state.cleared;
		const isActive = index === state.cleared;
		const status = card.querySelector('[data-status]');
		const feedback = card.querySelector('[data-feedback]');
		const controls = card.querySelectorAll('input, button');

		card.dataset.state = isCleared ? 'cleared' : isActive ? 'active' : 'locked';
		status.textContent = isCleared ? 'Cleared' : isActive ? 'Active' : 'Locked';

		controls.forEach((control) => {
			if (control.hasAttribute('data-reset')) {
				return;
			}

			control.disabled = !isActive || isCleared;
		});

		if (isCleared) {
			setFeedback(feedback, stages[index].success, false);
		} else if (isActive) {
			setFeedback(feedback, stages[index].ready, false);
		} else {
			setFeedback(feedback, stages[index].locked, false);
		}
	});

	progressTokens.forEach((token, index) => {
		token.classList.toggle('is-on', index < state.cleared);
	});

	renderLog();

	if (state.cleared >= stages.length) {
		finishPanel.classList.add('is-visible');
		rewardTarget.textContent = rewardFlag;
	} else {
		finishPanel.classList.remove('is-visible');
		rewardTarget.textContent = '';
	}
}

function bootConsoles() {
	if (!xssLog.textContent.trim()) {
		writeConsole(xssLog, 'Sandbox ready.\nTrigger a callback from inside the preview frame.', false);
	}

	if (!sqliLog.textContent.trim()) {
		writeConsole(sqliLog, 'Query runner idle.\nRaw input, normalized input, and executed query are not the same thing.', false);
	}

	if (!lfiLog.textContent.trim()) {
		writeConsole(lfiLog, 'File viewer idle.\nWatch the requested path, the decoded path, and the resolved path separately.', false);
	}
}

function handleXssMessage(event) {
	if (
		event.data?.type !== 'wtv-xss-clear' ||
		state.cleared !== 0 ||
		!xssFrame ||
		event.source !== xssFrame.contentWindow ||
		event.data?.token !== currentXssToken
	) {
		return;
	}

	writeConsole(
		xssLog,
		'Callback accepted from the sandbox.\nThe reflected payload executed and recovered the live review token.',
		false,
	);
	advanceStage(0);
}

function advanceStage(index) {
	if (state.cleared !== index) {
		return;
	}

	state.cleared = index + 1;
	saveState();
	render();
}

function renderLog() {
	const entries = ['Labs armed: xss -> sqli -> lfi.'];

	if (state.cleared >= 1) {
		entries.push('Preview sink executed. Query lab unlocked.');
	}

	if (state.cleared >= 2) {
		entries.push('WAF bypassed and hidden row reached. File viewer unlocked.');
	}

	if (state.cleared >= 3) {
		entries.push('Traversal escaped the fake root after decode and normalization. Reward channel open.');
	}

	logList.innerHTML = entries.map((entry) => `<li>${entry}</li>`).join('');
}

function setFeedback(element, message, isError) {
	if (!element) {
		return;
	}

	element.textContent = message;
	element.classList.toggle('is-error', Boolean(isError));
	element.classList.toggle('is-success', !isError && /cleared|reward/i.test(message));
}

function writeConsole(element, message, isError) {
	if (!element) {
		return;
	}

	element.textContent = message;
	element.classList.toggle('is-error', Boolean(isError));
}

function buildXssPreview(payload, token) {
	const filtered = payload
		.replace(/<script/gi, '&lt;script')
		.replace(/onerror/gi, 'blocked')
		.replace(/javascript:/gi, 'blocked:');

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<style>
body {
	margin: 0;
	padding: 18px;
	font-family: sans-serif;
	background: #08111a;
	color: #f7f0df;
}
.card {
	border: 1px solid rgba(255, 255, 255, 0.12);
	border-radius: 16px;
	padding: 16px;
	background: rgba(255, 255, 255, 0.04);
}
.note {
	margin-top: 12px;
	color: #aab6c6;
	font-size: 0.9rem;
}
</style>
</head>
<body>
	<div class="card">
		<h2>Preview</h2>
		<div>${filtered}</div>
		<p class="note">obvious script paths blocked, review token live, sink unchanged</p>
	</div>
	<script>
		window.__reviewToken = '${token}';
	</script>
</body>
</html>`;
}

function mintToken() {
	const buffer = new Uint8Array(6);
	crypto.getRandomValues(buffer);
	return Array.from(buffer, (chunk) => chunk.toString(16).padStart(2, '0')).join('');
}

function loadState() {
	try {
		const parsed = JSON.parse(localStorage.getItem(storageKey) ?? '{}');
		return {
			cleared: Math.max(0, Math.min(stages.length, Number(parsed.cleared) || 0)),
			hints: Array.isArray(parsed.hints) ? parsed.hints : [],
		};
	} catch {
		return { cleared: 0, hints: [] };
	}
}

function saveState() {
	localStorage.setItem(storageKey, JSON.stringify(state));
}
