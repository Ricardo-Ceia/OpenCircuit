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
	import { relativeTime, sortDevices } from '$lib/utils';

	type ActivityItem = {
		id: string;
		label: string;
		status: string;
		time: string;
	};

	let devices = $state<Device[]>([]);
	let activityItems = $state<ActivityItem[]>([]);
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
	let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let heartbeatTimer: ReturnType<typeof setInterval> | null = null;
	let lastPayloadStamp = '';
	let queuedPayload: DevicesResponse | null = null;
	let queuedFrame = 0;
	let hydrateInFlight = false;
	let shouldReconnect = true;

	const FALLBACK_POLL_MS = 10_000;
	const WS_HEARTBEAT_MS = 20_000;
	const WS_RECONNECT_MS = 2_200;

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

	function buildActivityItems(nextDevices: Device[]): ActivityItem[] {
		return [...nextDevices]
			.filter((d) => d.last_seen)
			.sort((a, b) => (b.last_seen ?? '').localeCompare(a.last_seen ?? ''))
			.slice(0, 8)
			.map((d) => ({
				id: d.ip,
				label: d.label,
				status: (d.status ?? 'offline') === 'online' ? 'seen online' : 'offline',
				time: relativeTime(d.last_seen)
			}));
	}

	function applyState(payload: DevicesResponse) {
		const stamp = payloadStamp(payload);
		if (stamp === lastPayloadStamp) {
			return;
		}
		lastPayloadStamp = stamp;

		devices = sortDevices(payload.devices ?? []);
		activityItems = buildActivityItems(devices);
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
		activityItems = buildActivityItems(devices);
		stats = {
			...stats,
			claimed: devices.filter((d) => d.identity_status === 'claimed').length,
			unidentified: devices.filter((d) => d.identity_status === 'unidentified').length
		};
	}

	function selectDevice(ip: string) {
		selectedIp = ip;
	}

	function queueStateApply(payload: DevicesResponse) {
		queuedPayload = payload;
		if (queuedFrame) {
			return;
		}
		queuedFrame = requestAnimationFrame(() => {
			queuedFrame = 0;
			if (!queuedPayload) {
				return;
			}
			const next = queuedPayload;
			queuedPayload = null;
			applyState(next);
		});
	}

	function clearReconnectTimer() {
		if (reconnectTimer) {
			clearTimeout(reconnectTimer);
			reconnectTimer = null;
		}
	}

	function clearHeartbeatTimer() {
		if (heartbeatTimer) {
			clearInterval(heartbeatTimer);
			heartbeatTimer = null;
		}
	}

	function startHeartbeat() {
		clearHeartbeatTimer();
		heartbeatTimer = setInterval(() => {
			if (!ws || ws.readyState !== WebSocket.OPEN) {
				return;
			}
			try {
				ws.send('ping');
			} catch {
				// socket lifecycle handlers will recover
			}
		}, WS_HEARTBEAT_MS);
	}

	function startFallbackPolling() {
		if (pollTimer) {
			return;
		}
		pollTimer = setInterval(() => {
			void hydrate();
		}, FALLBACK_POLL_MS);
	}

	async function hydrate() {
		if (hydrateInFlight) {
			return;
		}
		hydrateInFlight = true;
		try {
			const payload = await fetchDevices();
			applyState(payload);
		} catch {
			if (connection !== 'connected') {
				connection = 'disconnected';
			}
		} finally {
			hydrateInFlight = false;
		}
	}

	function connectWs() {
		const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
		const nextWs = new WebSocket(`${proto}//${window.location.host}/ws`);
		ws = nextWs;

		nextWs.onopen = () => {
			if (ws !== nextWs) {
				return;
			}
			connection = 'connected';
			clearReconnectTimer();
			startHeartbeat();
			void hydrate();
		};

		nextWs.onmessage = (event) => {
			if (ws !== nextWs) {
				return;
			}
		try {
				const payload = JSON.parse(event.data) as DevicesResponse;
				if (!payload || !Array.isArray(payload.devices) || typeof payload.last_scan !== 'string') {
					return;
				}
				queueStateApply(payload);
			} catch {
				// ignore malformed frames
			}
		};

		nextWs.onclose = () => {
			if (ws !== nextWs) {
				return;
			}
			ws = null;
			clearHeartbeatTimer();
			connection = 'disconnected';
			void hydrate();
			if (!shouldReconnect) {
				return;
			}
			clearReconnectTimer();
			reconnectTimer = setTimeout(() => {
				if (!shouldReconnect) {
					return;
				}
				connection = 'connecting';
				connectWs();
			}, WS_RECONNECT_MS);
		};

		nextWs.onerror = () => {
			if (ws !== nextWs) {
				return;
			}
			connection = 'disconnected';
		};
	}

	$effect(() => {
		shouldReconnect = true;
		void hydrate();
		startFallbackPolling();
		connectWs();

		return () => {
			shouldReconnect = false;
			clearReconnectTimer();
			clearHeartbeatTimer();
			if (pollTimer) {
				clearInterval(pollTimer);
				pollTimer = null;
			}
			if (queuedFrame) {
				cancelAnimationFrame(queuedFrame);
				queuedFrame = 0;
			}
			queuedPayload = null;
			if (ws) {
				const socket = ws;
				ws = null;
				socket.close();
			}
		};
	});
</script>

<RadarBackdrop />

<div class="shell">
	<TopBar {stats} {connection} />

	<main class="layout">
		<div class="left-stack">
			<DeviceList devices={devices} {selectedIp} onSelect={selectDevice} />
			<HintBar count={unnamedCount} />
		</div>

		<div class="center-stack">
			<DeviceDetail device={selectedDevice} onRenamed={patchRenamed} />
		</div>

		<div class="right-stack">
			<RadarPane devices={devices} {selectedIp} onSelect={selectDevice} />
			<ActivityFeed items={activityItems} />
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
		height: 100dvh;
		min-block-size: 0;
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
