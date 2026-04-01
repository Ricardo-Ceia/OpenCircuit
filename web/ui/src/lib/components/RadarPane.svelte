<script lang="ts">
	import type { Device } from '$lib/types';
	import { isOnline } from '$lib/utils';

	type Props = {
		devices: Device[];
		selectedIp: string | null;
		onSelect: (ip: string) => void;
	};

	let { devices, selectedIp, onSelect }: Props = $props();

	function hueFor(device: Device): number {
		if (device.identity_status === 'unidentified') return 42;
		if (device.identity_status === 'identified') return 185;
		return 140;
	}

	function position(index: number, total: number): { x: number; y: number } {
		const ring = index % 3;
		const angle = (index / Math.max(total, 1)) * Math.PI * 2;
		const radius = 24 + ring * 12;
		const x = 50 + Math.cos(angle) * radius;
		const y = 50 + Math.sin(angle) * radius;
		return { x, y };
	}
</script>

<section class="panel radar">
	<div class="radar-head">
		<div class="title">Signal Scope</div>
		<div class="sub">Relative contact cloud</div>
	</div>

	<div class="scope-wrap">
		<div class="scope"></div>
		<div class="rings"></div>
		<div class="sweep"></div>

		{#each devices as device, i}
			{@const p = position(i, devices.length)}
			<button
				type="button"
				class={`blip ${device.ip === selectedIp ? 'selected' : ''} ${isOnline(device) ? 'online' : 'offline'}`}
				onclick={() => onSelect(device.ip)}
				style={`left:${p.x}%;top:${p.y}%;--h:${hueFor(device)}`}
				title={`${device.label} • ${device.ip}`}
			>
				<span class="ping"></span>
			</button>
		{/each}
	</div>
</section>

<style>
	.radar {
		display: grid;
		gap: 0.8rem;
		padding: 0.9rem;
	}

	.radar-head {
		display: flex;
		justify-content: space-between;
		align-items: end;
	}

	.title {
		font-family: var(--display);
		font-size: 0.78rem;
		letter-spacing: 0.11em;
		text-transform: uppercase;
		color: var(--tone-text-bright);
	}

	.sub {
		font-size: 0.58rem;
		text-transform: uppercase;
		letter-spacing: 0.12em;
		color: var(--tone-muted);
	}

	.scope-wrap {
		position: relative;
		aspect-ratio: 1 / 1;
		border-radius: 999px;
		overflow: hidden;
		background:
			radial-gradient(circle at 50% 50%, color-mix(in oklab, var(--tone-online) 10%, transparent), transparent 55%),
			radial-gradient(circle at 50% 50%, color-mix(in oklab, var(--panel) 65%, black), color-mix(in oklab, var(--bg) 80%, black));
		border: 1px solid color-mix(in oklab, var(--tone-online) 22%, var(--edge-strong));
	}

	.rings,
	.scope {
		position: absolute;
		inset: 0;
	}

	.rings {
		background:
			radial-gradient(circle at center, transparent 23%, color-mix(in oklab, var(--tone-online) 12%, transparent) 24%, transparent 25%),
			radial-gradient(circle at center, transparent 41%, color-mix(in oklab, var(--tone-online) 10%, transparent) 42%, transparent 43%),
			radial-gradient(circle at center, transparent 59%, color-mix(in oklab, var(--tone-online) 8%, transparent) 60%, transparent 61%),
			linear-gradient(to right, transparent 49.7%, color-mix(in oklab, var(--tone-online) 10%, transparent) 50%, transparent 50.3%),
			linear-gradient(to bottom, transparent 49.7%, color-mix(in oklab, var(--tone-online) 10%, transparent) 50%, transparent 50.3%);
	}

	.sweep {
		position: absolute;
		inset: -18%;
		background: conic-gradient(from 0deg, transparent 0deg, transparent 310deg, color-mix(in oklab, var(--tone-online) 24%, transparent) 340deg, color-mix(in oklab, var(--tone-online) 4%, transparent) 360deg);
		animation: sweep 7.5s linear infinite;
		mix-blend-mode: screen;
		will-change: transform;
	}

	.blip {
		position: absolute;
		transform: translate(-50%, -50%);
		inline-size: 0.58rem;
		block-size: 0.58rem;
		border-radius: 999px;
		border: none;
		padding: 0;
		background: hsl(var(--h) 90% 58%);
		cursor: pointer;
		box-shadow: 0 0 0.8rem color-mix(in oklab, hsl(var(--h) 88% 60%) 58%, transparent);
	}

	.blip.offline {
		filter: grayscale(0.6);
		opacity: 0.55;
	}

	.blip.selected {
		outline: 2px solid color-mix(in oklab, white 70%, var(--tone-online));
		outline-offset: 2px;
	}

	.ping {
		position: absolute;
		inset: -0.4rem;
		border-radius: 999px;
		border: 1px solid color-mix(in oklab, hsl(var(--h) 88% 62%) 45%, transparent);
		animation: ping 3.2s ease-out infinite;
	}

	.blip.offline .ping {
		display: none;
	}

	@keyframes sweep {
		to {
			transform: rotate(360deg);
		}
	}

	@keyframes ping {
		0% {
			transform: scale(0.4);
			opacity: 0.8;
		}
		100% {
			transform: scale(1.5);
			opacity: 0;
		}
	}
</style>
