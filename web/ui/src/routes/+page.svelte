<script lang="ts">
	import ActivityFeed from '$lib/components/ActivityFeed.svelte';
	import DeviceDetail from '$lib/components/DeviceDetail.svelte';
	import DeviceList from '$lib/components/DeviceList.svelte';
	import HintBar from '$lib/components/HintBar.svelte';
	import RadarBackdrop from '$lib/components/RadarBackdrop.svelte';
	import RadarPane from '$lib/components/RadarPane.svelte';
	import TopBar from '$lib/components/TopBar.svelte';
	import { fetchDevices } from '$lib/api';
	import type { Device, DeviceStats, DevicesResponse } from '$lib/types';
	import { sortDevices } from '$lib/utils';

	let devices = $state<Device[]>([]);
	let stats = $state<DeviceStats>({
		total: 0,
		online: 0,
		offline: 0,
		claimed: 0,
		verified: 0,
		identified: 0,
		unidentified: 0
	});
	let selectedIp = $state<string | null>(null);
	let connection = $state<'connecting' | 'connected' | 'disconnected'>('connecting');
	let ws: WebSocket | null = null;
	let lastPayloadStamp = '';

	const selectedDevice = $derived(devices.find((d) => d.ip === selectedIp) ?? null);
	const unnamedCount = $derived(devices.filter((d) => d.identity_status === 'unidentified').length);

	function payloadStamp(payload: DevicesResponse): string {
		const parts = [
			String(payload.stats?.total ?? 0),
			String(payload.stats?.online ?? 0),
			String(payload.stats?.offline ?? 0),
			String(payload.stats?.unidentified ?? 0)
		];
		for (const d of payload.devices ?? []) {
			parts.push(
				`${d.ip}|${d.label}|${d.identity_status}|${d.status ?? ''}|${d.last_seen ?? ''}|${d.label_source ?? ''}`
			);
		}
		return parts.join('~');
	}

	function applyState(payload: DevicesResponse) {
		const stamp = payloadStamp(payload);
		if (stamp === lastPayloadStamp) {
			return;
		}
		lastPayloadStamp = stamp;

		devices = sortDevices(payload.devices ?? []);
		stats = payload.stats ?? stats;
		if (!selectedIp && devices.length > 0) {
			selectedIp = devices[0].ip;
		}
		if (selectedIp && !devices.some((d) => d.ip === selectedIp)) {
			selectedIp = devices[0]?.ip ?? null;
		}
	}

	function patchRenamed(mac: string, name: string) {
		devices = devices.map((d) => {
			if ((d.mac ?? '').toLowerCase() !== mac.toLowerCase()) {
				return d;
			}
			return {
				...d,
				label: name,
				label_source: 'known',
				identity_status: 'claimed',
				label_authoritative: true
			};
		});
		devices = sortDevices(devices);
		stats = {
			...stats,
			claimed: devices.filter((d) => d.identity_status === 'claimed').length,
			unidentified: devices.filter((d) => d.identity_status === 'unidentified').length
		};
	}

	async function hydrate() {
		try {
			const payload = await fetchDevices();
			applyState(payload);
		} catch {
			connection = 'disconnected';
		}
	}

	function connectWs() {
		const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
		ws = new WebSocket(`${proto}//${window.location.host}/ws`);

		ws.onopen = () => {
			connection = 'connected';
		};

		ws.onmessage = (event) => {
			try {
				const payload = JSON.parse(event.data) as DevicesResponse;
				applyState(payload);
			} catch {
				// ignore malformed frames
			}
		};

		ws.onclose = () => {
			connection = 'disconnected';
			setTimeout(() => {
				connection = 'connecting';
				connectWs();
			}, 2200);
		};

		ws.onerror = () => {
			connection = 'disconnected';
		};
	}

	$effect(() => {
		hydrate();
		connectWs();

		return () => {
			ws?.close();
		};
	});
</script>

<RadarBackdrop />

<div class="shell">
	<TopBar {stats} {connection} />

	<main class="layout">
		<div class="left-stack">
			<DeviceList devices={devices} {selectedIp} onSelect={(ip) => (selectedIp = ip)} />
			<HintBar count={unnamedCount} />
		</div>

		<div class="center-stack">
			<DeviceDetail device={selectedDevice} onRenamed={patchRenamed} />
		</div>

		<div class="right-stack">
			<RadarPane devices={devices} {selectedIp} onSelect={(ip) => (selectedIp = ip)} />
			<ActivityFeed devices={devices} />
		</div>
	</main>
</div>

<style>
	.shell {
		display: grid;
		gap: 0.75rem;
		padding: clamp(0.6rem, 1.4vw, 1rem);
		max-inline-size: 1800px;
		margin-inline: auto;
		min-block-size: 100dvh;
	}

	.layout {
		display: grid;
		grid-template-columns: minmax(18rem, 24rem) minmax(28rem, 1fr) minmax(16rem, 21rem);
		gap: 0.75rem;
		min-block-size: 0;
	}

	.left-stack,
	.center-stack,
	.right-stack {
		min-block-size: 0;
		display: grid;
		gap: 0.75rem;
	}

	.left-stack {
		grid-template-rows: minmax(18rem, 1fr) auto;
	}

	.right-stack {
		grid-template-rows: minmax(10rem, 1fr) minmax(10rem, 1fr);
	}

	@media (max-width: 1260px) {
		.layout {
			grid-template-columns: minmax(16rem, 20rem) minmax(0, 1fr);
		}

		.right-stack {
			grid-column: 1 / -1;
			grid-template-columns: repeat(2, minmax(0, 1fr));
			grid-template-rows: 1fr;
		}
	}

	@media (max-width: 920px) {
		.shell {
			padding: 0.45rem;
		}

		.layout {
			grid-template-columns: 1fr;
		}

		.right-stack {
			grid-template-columns: 1fr;
		}
	}
</style>
