<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>OpenCircuit Command Deck</title>
</svelte:head>

{@render children()}

<style>
	:global(:root) {
		--bg: #060b11;
		--bg-alt: #0a1019;
		--panel: #0d1420;
		--panel-alt: #0f1a2a;
		--edge-soft: rgba(122, 166, 206, 0.16);
		--edge-strong: rgba(128, 190, 255, 0.25);

		--tone-online: #34e66f;
		--tone-online-soft: #7bf4a4;
		--tone-cyan: #43d6ff;
		--tone-warning: #f1b13f;
		--tone-warning-soft: #ffdca3;
		--tone-offline: #ff5f72;

		--tone-text: #d4dfeb;
		--tone-text-bright: #f2f7ff;
		--tone-muted: #6b7c92;
		--tone-muted-bright: #95a8bf;

		--display: 'Cascadia Mono', 'Cascadia Code', 'SFMono-Regular', 'Consolas', 'Liberation Mono',
			'Menlo', 'Monaco', monospace;
		--body: 'Cascadia Mono', 'Cascadia Code', 'SFMono-Regular', 'Consolas', 'Liberation Mono',
			'Menlo', 'Monaco', monospace;
	}

	:global(*) {
		box-sizing: border-box;
	}

	:global(html),
	:global(body) {
		margin: 0;
		padding: 0;
		font-family: var(--body);
		font-size: 14px;
		line-height: 1.45;
		background:
			radial-gradient(120% 140% at 20% -10%, rgba(82, 194, 255, 0.12), transparent 60%),
			radial-gradient(120% 140% at 80% 110%, rgba(69, 242, 139, 0.08), transparent 58%),
			linear-gradient(180deg, var(--bg-alt), var(--bg));
		color: var(--tone-text);
		min-height: 100%;
		overflow: hidden;
	}

	:global(body::before) {
		content: '';
		position: fixed;
		inset: 0;
		pointer-events: none;
		background: repeating-linear-gradient(
			180deg,
			transparent 0,
			transparent 2px,
			rgba(5, 8, 14, 0.18) 3px,
			rgba(5, 8, 14, 0.18) 4px
		);
		opacity: 0.35;
		z-index: 5;
	}

	:global(button),
	:global(input) {
		font: inherit;
	}

	:global(.panel) {
		background: linear-gradient(
			160deg,
			color-mix(in oklab, var(--panel) 90%, black),
			color-mix(in oklab, var(--panel-alt) 92%, black)
		);
		border: 1px solid var(--edge-soft);
		border-radius: 0.72rem;
		backdrop-filter: blur(2px);
	}

	:global(.panel-glow) {
		box-shadow:
			0 0 0 1px color-mix(in oklab, var(--tone-online) 16%, transparent),
			0 0 1.6rem color-mix(in oklab, var(--tone-online) 10%, transparent);
	}

	:global(.panel-warning) {
		border-color: color-mix(in oklab, var(--tone-warning) 36%, var(--edge-soft));
		box-shadow: 0 0 1.3rem color-mix(in oklab, var(--tone-warning) 10%, transparent);
	}

	@media (prefers-reduced-motion: reduce) {
		:global(*),
		:global(*::before),
		:global(*::after) {
			animation-duration: 0.01ms !important;
			animation-iteration-count: 1 !important;
			transition-duration: 0.01ms !important;
			scroll-behavior: auto !important;
		}
	}
</style>
