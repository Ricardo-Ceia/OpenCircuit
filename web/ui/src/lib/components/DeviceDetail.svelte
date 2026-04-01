<script lang="ts">
	import { saveDeviceName, normalizeSources } from '$lib/api';
	import type { Device } from '$lib/types';
	import { deviceClue, isNamable, isOnline, relativeTime } from '$lib/utils';

	type Props = {
		device: Device | null;
		onRenamed: (mac: string, name: string) => void;
	};

	let { device, onRenamed }: Props = $props();

	let inputValue = $state('');
	let isSaving = $state(false);
	let notice = $state<{ kind: 'ok' | 'error'; message: string } | null>(null);

	$effect(() => {
		if (!device) {
			inputValue = '';
			return;
		}
		inputValue = device.identity_status === 'claimed' ? (device.label ?? '') : '';
	});

	async function commitName() {
		if (!device || !isNamable(device)) {
			return;
		}
		const name = inputValue.trim();
		if (!name) {
			notice = { kind: 'error', message: 'Name cannot be empty' };
			return;
		}

		isSaving = true;
		notice = null;
		try {
			await saveDeviceName(device.mac!, name);
			onRenamed(device.mac!, name);
			notice = { kind: 'ok', message: `Saved as "${name}"` };
		} catch (err) {
			notice = { kind: 'error', message: err instanceof Error ? err.message : 'Save failed' };
		} finally {
			isSaving = false;
		}
	}

	function field(value: unknown, fallback = '—'): string {
		if (value === null || value === undefined || value === '') {
			return fallback;
		}
		return String(value);
	}
</script>

<section class="panel panel-detail">
	{#if !device}
		<div class="empty">
			<div class="empty-title">No contact selected</div>
			<div class="empty-sub">Select a device from the manifest to inspect and name it.</div>
		</div>
	{:else}
		<header class="detail-head">
			<div>
				<div class="kicker">Active Contact</div>
				<div class="label">{device.label}</div>
			</div>
			<div class={`identity ${device.identity_status}`}>{device.identity_status}</div>
		</header>

		<div class="status-line">
			<span class={`dot ${isOnline(device) ? 'online' : 'offline'}`}></span>
			<span>{isOnline(device) ? 'Online now' : `Offline · ${relativeTime(device.last_seen)}`}</span>
		</div>

		{#if isNamable(device)}
			<div class="rename-row">
				<input
					type="text"
					bind:value={inputValue}
					placeholder="Assign a human name"
					onkeydown={(event) => event.key === 'Enter' && commitName()}
				/>
				<button type="button" onclick={commitName} disabled={isSaving}>
					{isSaving ? 'Saving…' : 'Save Name'}
				</button>
			</div>
		{/if}

		{#if notice}
			<div class={`notice ${notice.kind}`}>{notice.message}</div>
		{/if}

		<div class="grid">
			<div class="row">
				<div class="key">IP</div>
				<div class="val">{field(device.ip)}</div>
			</div>
			<div class="row">
				<div class="key">MAC</div>
				<div class="val mono">{field(device.mac, 'unknown')}</div>
			</div>
			<div class="row">
				<div class="key">Label source</div>
				<div class="val">{field(device.label_source)}</div>
			</div>
			<div class="row">
				<div class="key">Clue</div>
				<div class="val">{field(deviceClue(device), 'No auxiliary clue')}</div>
			</div>
			<div class="row">
				<div class="key">Hostname</div>
				<div class="val">{field(device.hostname)}</div>
			</div>
			<div class="row">
				<div class="key">Vendor</div>
				<div class="val">{field(device.vendor)}</div>
			</div>
			<div class="row">
				<div class="key">Manufacturer</div>
				<div class="val">{field(device.fingerprint?.manufacturer)}</div>
			</div>
			<div class="row">
				<div class="key">Model</div>
				<div class="val">{field(device.fingerprint?.model)}</div>
			</div>
			<div class="row">
				<div class="key">Type</div>
				<div class="val">{field(device.fingerprint?.device_type)}</div>
			</div>
			<div class="row">
				<div class="key">First seen</div>
				<div class="val">{relativeTime(device.first_seen)}</div>
			</div>
			<div class="row">
				<div class="key">Last seen</div>
				<div class="val">{relativeTime(device.last_seen)}</div>
			</div>
			<div class="row">
				<div class="key">Scan channels</div>
				<div class="val">{normalizeSources(device).join(', ') || '—'}</div>
			</div>
			<div class="row row-wide">
				<div class="key">Services</div>
				<div class="val wrap">{(device.services ?? []).join(', ') || 'No probes exposed'}</div>
			</div>
		</div>
	{/if}
</section>

<style>
	.panel-detail {
		padding: 1rem 1rem 1.1rem;
		display: grid;
		gap: 0.85rem;
		min-block-size: 0;
		overflow: auto;
	}

	.empty {
		place-self: center;
		text-align: center;
		max-inline-size: 24rem;
		padding: 2rem 1rem;
	}

	.empty-title {
		font-family: var(--display);
		font-size: 1rem;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		color: var(--tone-text-bright);
		margin-bottom: 0.45rem;
	}

	.empty-sub {
		font-size: 0.75rem;
		line-height: 1.6;
		color: var(--tone-muted-bright);
	}

	.detail-head {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
		padding-bottom: 0.7rem;
		border-bottom: 1px solid var(--edge-soft);
	}

	.kicker {
		font-size: 0.6rem;
		text-transform: uppercase;
		letter-spacing: 0.16em;
		color: var(--tone-muted);
		margin-bottom: 0.35rem;
	}

	.label {
		font-family: var(--display);
		font-size: clamp(1rem, 1.8vw, 1.45rem);
		line-height: 1.1;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--tone-text-bright);
	}

	.identity {
		font-size: 0.6rem;
		letter-spacing: 0.11em;
		text-transform: uppercase;
		padding: 0.25rem 0.5rem;
		border-radius: 0.25rem;
		border: 1px solid transparent;
		white-space: nowrap;
	}

	.identity.claimed,
	.identity.verified {
		color: var(--tone-online-soft);
		border-color: color-mix(in oklab, var(--tone-online) 30%, transparent);
		background: color-mix(in oklab, var(--tone-online) 10%, transparent);
	}

	.identity.identified {
		color: var(--tone-cyan);
		border-color: color-mix(in oklab, var(--tone-cyan) 32%, transparent);
		background: color-mix(in oklab, var(--tone-cyan) 9%, transparent);
	}

	.identity.unidentified {
		color: var(--tone-warning);
		border-color: color-mix(in oklab, var(--tone-warning) 32%, transparent);
		background: color-mix(in oklab, var(--tone-warning) 10%, transparent);
	}

	.status-line {
		display: inline-flex;
		align-items: center;
		gap: 0.45rem;
		font-size: 0.69rem;
		text-transform: uppercase;
		letter-spacing: 0.09em;
		color: var(--tone-muted-bright);
	}

	.dot {
		inline-size: 0.42rem;
		block-size: 0.42rem;
		border-radius: 999px;
	}

	.dot.online {
		background: var(--tone-online);
		box-shadow: 0 0 0.55rem color-mix(in oklab, var(--tone-online) 75%, transparent);
	}

	.dot.offline {
		background: var(--tone-offline);
	}

	.rename-row {
		display: grid;
		grid-template-columns: 1fr auto;
		gap: 0.5rem;
	}

	.rename-row input {
		font: inherit;
		font-size: 0.78rem;
		padding: 0.62rem 0.68rem;
		border-radius: 0.38rem;
		border: 1px solid var(--edge-strong);
		background: color-mix(in oklab, var(--panel-alt) 88%, black);
		color: var(--tone-text-bright);
		outline: none;
		transition: border-color 180ms ease, box-shadow 180ms ease;
	}

	.rename-row input:focus {
		border-color: color-mix(in oklab, var(--tone-online) 45%, white 8%);
		box-shadow: 0 0 0 2px color-mix(in oklab, var(--tone-online) 14%, transparent);
	}

	.rename-row button {
		font: inherit;
		font-size: 0.68rem;
		text-transform: uppercase;
		letter-spacing: 0.12em;
		padding: 0.55rem 0.75rem;
		border: 1px solid color-mix(in oklab, var(--tone-online) 38%, var(--edge-strong));
		border-radius: 0.35rem;
		color: var(--tone-online-soft);
		background: color-mix(in oklab, var(--tone-online) 8%, var(--panel-alt));
		cursor: pointer;
		transition: transform 140ms ease, border-color 140ms ease;
	}

	.rename-row button:hover:not(:disabled) {
		transform: translateY(-1px);
		border-color: color-mix(in oklab, var(--tone-online) 62%, white 10%);
	}

	.rename-row button:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}

	.notice {
		font-size: 0.7rem;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		padding: 0.42rem 0.55rem;
		border-radius: 0.32rem;
	}

	.notice.ok {
		color: var(--tone-online-soft);
		background: color-mix(in oklab, var(--tone-online) 12%, transparent);
		border: 1px solid color-mix(in oklab, var(--tone-online) 30%, transparent);
	}

	.notice.error {
		color: color-mix(in oklab, var(--tone-offline) 75%, white 5%);
		background: color-mix(in oklab, var(--tone-offline) 12%, transparent);
		border: 1px solid color-mix(in oklab, var(--tone-offline) 28%, transparent);
	}

	.grid {
		display: grid;
		gap: 0.35rem;
	}

	.row {
		display: grid;
		grid-template-columns: 8.1rem minmax(0, 1fr);
		gap: 0.45rem;
		align-items: stretch;
	}

	.key,
	.val {
		padding: 0.46rem 0.56rem;
		border-radius: 0.3rem;
		background: color-mix(in oklab, var(--panel-alt) 84%, black);
		border: 1px solid var(--edge-soft);
	}

	.key {
		font-size: 0.63rem;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: var(--tone-muted-bright);
	}

	.val {
		font-size: 0.72rem;
		color: var(--tone-text);
	}

	.val.mono {
		font-family: var(--display);
	}

	.wrap {
		line-break: anywhere;
	}

	.row-wide {
		grid-template-columns: 8.1rem minmax(0, 1fr);
	}

	@media (max-width: 900px) {
		.row {
			grid-template-columns: 1fr;
		}
	}
</style>
