<script lang="ts">
	import type { DeviceStats } from '$lib/types';

	type Props = {
		stats: DeviceStats;
		connection: 'connecting' | 'connected' | 'disconnected';
	};

	let { stats, connection }: Props = $props();
</script>

<header class="topbar panel panel-glow">
	<div class="brand">
		<div class="brand-kicker">Network Operations</div>
		<div class="brand-main">OpenCircuit Command Deck</div>
	</div>

	<div class="connection">
		<span class={`dot ${connection}`}></span>
		<span class="label">
			{connection === 'connected'
				? 'Live Feed'
				: connection === 'connecting'
					? 'Dialing'
					: 'Signal Lost'}
		</span>
	</div>

	<div class="metrics">
		<div class="metric online">
			<span class="value">{stats.online}</span>
			<span class="name">online</span>
		</div>
		<div class="metric offline">
			<span class="value">{stats.offline}</span>
			<span class="name">offline</span>
		</div>
		<div class="metric unnamed">
			<span class="value">{stats.unidentified}</span>
			<span class="name">unnamed</span>
		</div>
	</div>
</header>

<style>
	.topbar {
		display: grid;
		grid-template-columns: 1fr auto auto;
		align-items: center;
		gap: 1.5rem;
		padding: 1rem 1.25rem;
	}

	.brand-kicker {
		font-size: 0.64rem;
		letter-spacing: 0.22em;
		text-transform: uppercase;
		color: var(--tone-muted);
		margin-bottom: 0.3rem;
	}

	.brand-main {
		font-family: var(--display);
		font-size: clamp(1.05rem, 1.4vw, 1.45rem);
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--tone-text-bright);
	}

	.connection {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.55rem 0.8rem;
		border: 1px solid var(--edge-strong);
		background: color-mix(in oklab, var(--panel-alt) 85%, black);
		border-radius: 999px;
	}

	.dot {
		inline-size: 0.5rem;
		block-size: 0.5rem;
		border-radius: 999px;
		background: var(--tone-warning);
		box-shadow: 0 0 0.6rem color-mix(in oklab, var(--tone-warning) 60%, transparent);
	}

	.dot.connected {
		background: var(--tone-online);
		box-shadow: 0 0 0.8rem color-mix(in oklab, var(--tone-online) 70%, transparent);
	}

	.dot.disconnected {
		background: var(--tone-offline);
		box-shadow: 0 0 0.75rem color-mix(in oklab, var(--tone-offline) 65%, transparent);
	}

	.label {
		font-size: 0.68rem;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--tone-muted-bright);
	}

	.metrics {
		display: flex;
		align-items: stretch;
		gap: 0.55rem;
	}

	.metric {
		display: grid;
		min-inline-size: 4.4rem;
		padding: 0.45rem 0.65rem;
		border: 1px solid var(--edge-strong);
		background: color-mix(in oklab, var(--panel-alt) 88%, black);
		border-radius: 0.35rem;
	}

	.value {
		font-family: var(--display);
		font-size: 1rem;
		line-height: 1;
		font-variant-numeric: tabular-nums;
		min-inline-size: 2ch;
	}

	.name {
		font-size: 0.62rem;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		color: var(--tone-muted);
		margin-top: 0.35rem;
	}

	.metric.online .value {
		color: var(--tone-online);
	}

	.metric.offline .value {
		color: var(--tone-offline);
	}

	.metric.unnamed .value {
		color: var(--tone-warning);
	}

	@media (max-width: 900px) {
		.topbar {
			grid-template-columns: 1fr;
			gap: 0.9rem;
		}

		.metrics {
			justify-content: flex-start;
			flex-wrap: wrap;
		}
	}
</style>
