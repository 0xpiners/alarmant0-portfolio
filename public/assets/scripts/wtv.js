const routes = {
	sqli: '/wtv/lab/sqli',
	lfi: '/wtv/lab/files',
	finalize: '/wtv/lab/finalize',
};

const storageKey = 'wtv-progress-v6';
const rewardFlag = 'wtv{verify_more_assume_less_chain_the_findings}';
const xssStageFlag = 'wtv{xss_rehydration_beats_blacklists}';

const stages = [
	{
		id: 'xss',
		success: 'XSS lab cleared. Metadata became markup again and the frame-state marker was recovered.',
		ready: 'Preview lab armed. Watch where text becomes HTML for a second time.',
		locked: 'Solve the previous lab first.',
		hints: [
			'The input is stored as metadata before the preview renders it back into HTML.',
			'The obvious strings are filtered, but the review marker lives in frame state rather than visible page text.',
		],
	},
	{
		id: 'sqli',
		success: 'SQLi lab cleared. The union branch survived the raw filter and leaked the shadow notes.',
		ready: 'Query lab armed. The WAF sees raw bytes. The planner sees normalized SQL.',
		locked: 'Clear the XSS lab first.',
		hints: [
			'The raw filter only sees contiguous keywords, but parsing happens after block comments disappear.',
			'The base query expects three projected columns, and the interesting data is not in accounts.',
		],
	},
	{
		id: 'lfi',
		success: 'LFI lab cleared. Admission, decode, and normalization disagreed about the target path.',
		ready: 'File viewer armed. Compare the ticketed path, the mount, and the resolved target.',
		locked: 'Clear the SQLi lab first.',
		hints: [
			'Access is granted only to docs/*.txt on the first pass.',
			'A second decode happens after traversal stripping, and the mount root starts deeper than it looks.',
		],
	},
];

const state = loadState();
let currentXssToken = '';

const stageCards = Array.from(document.querySelectorAll('[data-stage-card]'));
const progressTokens = Array.from(document.querySelectorAll('[data-progress-token]'));
const sidebarStages = Array.from(document.querySelectorAll('[data-sidebar-stage]'));
const logList = document.querySelector('[data-challenge-log]');
const finishPanel = document.querySelector('[data-finish]');
const rewardTarget = document.querySelector('[data-reward-flag]');
const resetButton = document.querySelector('[data-reset]');
const activeLabel = document.querySelector('[data-active-label]');
const clearedCount = document.querySelector('[data-cleared-count]');
const hintCount = document.querySelector('[data-hint-count]');
const meterFill = document.querySelector('[data-meter-fill]');
const meterLabel = document.querySelector('[data-meter-label]');
const finalForm = document.querySelector('[data-final-form]');
const finalXssInput = document.querySelector('[data-final-xss]');
const finalSqliInput = document.querySelector('[data-final-sqli]');
const finalLfiInput = document.querySelector('[data-final-lfi]');
const finalLog = document.querySelector('[data-final-log]');
const finalFeedback = document.querySelector('[data-final-feedback]');

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
			renderOverview();
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
			[
				`preview = rebuilt with ${payload.length} bytes`,
				'sink = data attribute -> innerHTML',
				'review = marker rotated into frame state',
			].join('\n'),
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
				`signature = ${data.signature}`,
				`projection = ${response.headers.get('X-WTV-Projection') ?? '?'} columns`,
				`route = ${response.headers.get('X-WTV-Route') ?? 'sqli'}`,
				`raw = ${data.raw}`,
				`normalized = ${data.normalized}`,
				'',
				data.query,
				'',
				...data.notes.map((note) => `> ${note}`),
				'',
				`rows = ${JSON.stringify(data.rows, null, 2)}`,
				data.cleared ? `\nflag = ${data.flag}` : '',
			].join('\n'),
			data.signature !== 'passed',
		);

		if (data.cleared) {
			state.flags.sqli = data.flag;
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
				`ticket = ${response.headers.get('X-WTV-Ticket') ?? 'unknown'}`,
				`requested = ${data.requested}`,
				`decoded = ${data.decoded}`,
				`mount = ${response.headers.get('X-WTV-Mount') ?? 'unknown'}`,
				`resolved = ${response.headers.get('X-WTV-Resolved') ?? 'unknown'}`,
				'',
				data.content,
				data.cleared ? `\nflag = ${data.flag}` : '',
			].join('\n'),
			(response.headers.get('X-WTV-Ticket') ?? 'denied') !== 'granted',
		);

		if (data.cleared) {
			state.flags.lfi = data.flag;
			advanceStage(2);
		}
	});

	finalForm?.addEventListener('submit', async (event) => {
		event.preventDefault();

		if (state.cleared < stages.length || state.finalCleared) {
			return;
		}

		const xss = finalXssInput?.value.trim() ?? '';
		const sqli = finalSqliInput?.value.trim() ?? '';
		const lfi = finalLfiInput?.value.trim() ?? '';

		if (!xss || !sqli || !lfi) {
			writeConsole(finalLog, 'Need all three stage flags before sealing the run.', true);
			setFeedback(finalFeedback, 'Missing one or more flags.', true);
			return;
		}

		const response = await fetch(routes.finalize, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ xss, sqli, lfi }),
			cache: 'no-store',
		});
		const data = await response.json();

		writeConsole(
			finalLog,
			[
				`status = ${response.status}`,
				`note = ${data.note}`,
				data.cleared ? `flag = ${data.flag}` : 'gate = still closed',
			].join('\n'),
			!data.cleared,
		);

		setFeedback(finalFeedback, data.note, !data.cleared);

		if (data.cleared) {
			state.finalCleared = true;
			state.flags.final = data.flag;
			saveState();
			render();
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
		const isOn = index < stages.length ? index < state.cleared : state.finalCleared;
		token.classList.toggle('is-on', isOn);
	});

	renderOverview();

	renderLog();

	if (state.cleared >= stages.length) {
		finishPanel.classList.add('is-visible');
		toggleFinalControls(state.finalCleared);
		if (state.finalCleared) {
			rewardTarget.textContent = state.flags.final || rewardFlag;
			setFeedback(finalFeedback, 'Final gate cleared.', false);
		} else {
			rewardTarget.textContent = '';
			setFeedback(finalFeedback, 'Submit the three lab flags.', false);
		}
	} else {
		finishPanel.classList.remove('is-visible');
		rewardTarget.textContent = '';
	}
}

function renderOverview() {
	const nextStage = stages[state.cleared]?.id ?? (state.finalCleared ? 'sealed' : 'final');
	const usedHints = state.hints.reduce((total, value) => total + Math.max(0, Number(value) || 0), 0);
	const percent = Math.round(((state.cleared + (state.finalCleared ? 1 : 0)) / (stages.length + 1)) * 100);

	if (activeLabel) {
		activeLabel.textContent = nextStage;
	}

	if (clearedCount) {
		clearedCount.textContent = String(state.cleared);
	}

	if (hintCount) {
		hintCount.textContent = String(usedHints);
	}

	if (meterFill) {
		meterFill.style.width = `${percent}%`;
	}

	if (meterLabel) {
		meterLabel.textContent = `${percent}%`;
	}

	sidebarStages.forEach((stage, index) => {
		const copy = stage.querySelector('[data-sidebar-stage-copy]');
		const isFinal = index === stages.length;
		const isCleared = isFinal ? state.finalCleared : index < state.cleared;
		const isActive = isFinal ? state.cleared >= stages.length && !state.finalCleared : index === state.cleared;
		const stageState = isCleared ? 'cleared' : isActive ? 'active' : 'locked';

		stage.dataset.state = stageState;

		if (copy) {
			copy.textContent = isCleared ? 'Cleared' : isActive ? 'Active' : 'Locked';
		}
	});
}

function bootConsoles() {
	if (!xssLog.textContent.trim()) {
		writeConsole(xssLog, 'Preview sink idle.\nLook for metadata that becomes HTML again inside the frame.', false);
	}

	if (!sqliLog.textContent.trim()) {
		writeConsole(sqliLog, 'Query runner idle.\nRaw filtering, normalized SQL, and the executed plan are not the same surface.', false);
	}

	if (!lfiLog.textContent.trim()) {
		writeConsole(lfiLog, 'File viewer idle.\nWatch the ticket, the mount, and the resolved path separately.', false);
	}

	if (!finalLog.textContent.trim()) {
		writeConsole(finalLog, 'Final gate idle.\nBring back the three stage flags to seal the run.', false);
	}
}

function handleXssMessage(event) {
	if (
		event.data?.type !== 'wtv-xss-clear' ||
		state.cleared !== 0 ||
		!xssFrame ||
		event.source !== xssFrame.contentWindow ||
		event.data?.token !== currentXssToken ||
		event.data?.proof !== 'frame-css'
	) {
		return;
	}

	writeConsole(
		xssLog,
		`Callback accepted from the sandbox.\nThe payload reached the rehydrated sink and recovered the live frame-state marker.\nflag = ${
			event.data.flag ?? xssStageFlag
		}`,
		false,
	);
	state.flags.xss = event.data.flag ?? xssStageFlag;
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
		entries.push('Metadata sink re-entered HTML. Query lab unlocked.');
	}

	if (state.cleared >= 2) {
		entries.push('Raw filter lost to normalized SQL. File viewer unlocked.');
	}

	if (state.cleared >= 3) {
		entries.push('Mount escaped after the second decode. Final gate unlocked.');
	}

	if (state.finalCleared) {
		entries.push('Run sealed. Final reward issued.');
	}

	renderLogEntries(entries);
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
		.replace(/onload/gi, 'blocked')
		.replace(/autofocus/gi, 'blocked')
		.replace(/javascript:/gi, 'blocked:');

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<style>
:root {
	--review-token: ${token};
}
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
.slot {
	min-height: 54px;
	padding: 12px;
	border-radius: 12px;
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
	<div class="card" data-profile data-bio="${escapeAttribute(filtered)}">
		<h2>Preview</h2>
		<div class="slot" data-slot>render pending...</div>
		<p class="note">path = metadata -> fragment // review state pinned to frame style</p>
	</div>
	<script>
		const profile = document.querySelector('[data-profile]');
		const slot = document.querySelector('[data-slot]');
		const reviewToken = getComputedStyle(document.documentElement).getPropertyValue('--review-token').trim();
		const stageFlag = '${xssStageFlag}';

		slot.innerHTML = profile.dataset.bio;
		window.reportPreview = (value) => {
			if (value === reviewToken) {
				parent.postMessage({ type: 'wtv-xss-clear', token: value, proof: 'frame-css', flag: stageFlag }, '*');
			}
		};
	</script>
</body>
</html>`;
}

function renderLogEntries(entries) {
	if (!logList) {
		return;
	}

	logList.replaceChildren(
		...entries.map((entry) => {
			const item = document.createElement('li');
			item.textContent = entry;
			return item;
		}),
	);
}

function toggleFinalControls(isLocked) {
	const controls = finalForm?.querySelectorAll('input, button') ?? [];

	controls.forEach((control) => {
		control.disabled = Boolean(isLocked);
	});
}

function escapeAttribute(value) {
	return value
		.replace(/&/g, '&amp;')
		.replace(/"/g, '&quot;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
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
			flags: typeof parsed.flags === 'object' && parsed.flags ? parsed.flags : {},
			finalCleared: Boolean(parsed.finalCleared),
		};
	} catch {
		return { cleared: 0, hints: [], flags: {}, finalCleared: false };
	}
}

function saveState() {
	localStorage.setItem(storageKey, JSON.stringify(state));
}
