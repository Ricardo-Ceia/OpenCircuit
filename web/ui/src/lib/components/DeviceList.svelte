<script lang="ts">
	import type { Device } from '$lib/types';
	import { deviceClue, isOnline } from '$lib/utils';

	type Props = {
		devices: Device[];
		selectedIp: string | null;
		onSelect: (ip: string) => void;
	};

	let { devices, selectedIp, onSelect }: Props = $props();
</script>

<section class="panel panel-list">
	<div class="panel-head">
		<div class="title">Device Manifest</div>
		<div class="subtitle">{devices.length} tracked contacts</div>
	</div>

	{#if devices.length === 0}
		<div class="empty">Listening for first scan pulse…</div>
	{:else}
		<div class="cards">
			{#each devices as device (device.ip)}
				<button
					type="button"
					class={`card ${device.ip === selectedIp ? 'selected' : ''} ${device.identity_status}`}
					onclick={() => onSelect(device.ip)}
				>
					<div class="card-top">
						<div class="dot {isOnline(device) ? 'online' : 'offline'}"></div>
						<div class="label" title={device.label}>{device.label}</div>
						<div class="identity {device.identity_status}">{device.identity_status}</div>
					</div>
					<div class="card-bottom">
						<span class="ip">{device.ip}</span>
						<span class="clue">{deviceClue(device)}</span>
					</div>
				</button>
			{/each}
		</div>
	{/if}
</section>

<style>
	.panel-list {
		display: grid;
		grid-template-rows: auto 1fr;
		min-block-size: 0;
	}

	.panel-head {
		display: flex;
		justify-content: space-between;
		align-items: end;
		padding: 0.9rem 1rem;
		border-bottom: 1px solid var(--edge-soft);
	}

	.title {
		font-family: var(--display);
		font-size: 0.88rem;
		text-transform: uppercase;
		letter-spacing: 0.11em;
		color: var(--tone-text-bright);
	}

	.subtitle {
		font-size: 0.63rem;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		color: var(--tone-muted);
	}

	.empty {
		display: grid;
		place-content: center;
		font-size: 0.78rem;
		letter-spacing: 0.09em;
		text-transform: uppercase;
		color: var(--tone-muted-bright);
		padding: 2rem;
	}

	.cards {
		overflow: auto;
		padding: 0.45rem;
		display: grid;
		gap: 0.4rem;
	}

	.card {
		display: grid;
		gap: 0.45rem;
		text-align: left;
		padding: 0.6rem 0.7rem;
		border: 1px solid var(--edge-soft);
		background: linear-gradient(
			150deg,
			color-mix(in oklab, var(--panel) 82%, black),
			color-mix(in oklab, var(--panel-alt) 92%, black)
		);
		color: var(--tone-text);
		border-radius: 0.5rem;
		cursor: pointer;
		transition: transform 180ms ease, border-color 180ms ease, box-shadow 180ms ease;
	}

	.card:hover {
		transform: translateY(-1px);
		border-color: color-mix(in oklab, var(--tone-online) 32%, var(--edge-strong));
	}

	.card.selected {
		border-color: color-mix(in oklab, var(--tone-online) 60%, white 10%);
		box-shadow: 0 0 0 1px color-mix(in oklab, var(--tone-online) 40%, transparent),
			0 0 1.1rem color-mix(in oklab, var(--tone-online) 18%, transparent);
	}

	.card.selected.unidentified {
		border-color: color-mix(in oklab, var(--tone-warning) 58%, white 8%);
		box-shadow: 0 0 0 1px color-mix(in oklab, var(--tone-warning) 35%, transparent),
			0 0 1rem color-mix(in oklab, var(--tone-warning) 14%, transparent);
	}

	.card-top {
		display: grid;
		grid-template-columns: auto 1fr auto;
		align-items: center;
		gap: 0.5rem;
	}

	.dot {
		inline-size: 0.48rem;
		block-size: 0.48rem;
		border-radius: 999px;
	}

	.dot.online {
		background: var(--tone-online);
		box-shadow: 0 0 0.65rem color-mix(in oklab, var(--tone-online) 70%, transparent);
	}

	.dot.offline {
		background: var(--tone-offline);
	}

	.label {
		font-size: 0.8rem;
		line-height: 1.15;
		color: var(--tone-text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.identity {
		font-size: 0.58rem;
		letter-spacing: 0.11em;
		text-transform: uppercase;
		padding: 0.1rem 0.35rem;
		border-radius: 0.2rem;
		border: 1px solid transparent;
	}

	.identity.claimed,
	.identity.verified {
		color: var(--tone-online-soft);
		border-color: color-mix(in oklab, var(--tone-online) 25%, transparent);
		background: color-mix(in oklab, var(--tone-online) 10%, transparent);
	}

	.identity.identified {
		color: var(--tone-cyan);
		border-color: color-mix(in oklab, var(--tone-cyan) 28%, transparent);
		background: color-mix(in oklab, var(--tone-cyan) 9%, transparent);
	}

	.identity.unidentified {
		color: var(--tone-warning);
		border-color: color-mix(in oklab, var(--tone-warning) 30%, transparent);
		background: color-mix(in oklab, var(--tone-warning) 10%, transparent);
	}

	.card-bottom {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: 0.55rem;
		align-items: center;
	}

	.ip {
		font-size: 0.62rem;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--tone-muted);
	}

	.clue {
		font-size: 0.68rem;
		color: var(--tone-muted-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

</style>
