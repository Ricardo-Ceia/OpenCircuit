<script lang="ts">
	import ActivityFeed from '$lib/components/ActivityFeed.svelte';
	import DeviceDetail from '$lib/components/DeviceDetail.svelte';
	import DeviceList from '$lib/components/DeviceList.svelte';
	import { applyDevicesPayload, createInitialDashboardState, patchRenamedDevice } from '$lib/dashboard-state';
	import HintBar from '$lib/components/HintBar.svelte';
	import { LiveDeviceFeed, type ConnectionState } from '$lib/live-feed';
	import RadarBackdrop from '$lib/components/RadarBackdrop.svelte';
	import RadarPane from '$lib/components/RadarPane.svelte';
	import TopBar from '$lib/components/TopBar.svelte';
	import { estimateOnlineDevices, fetchDevices } from '$lib/api';
	import type { Device } from '$lib/types';

	const initialState = createInitialDashboardState();
	let devices = $state<Device[]>(initialState.devices);
	let activityItems = $state(initialState.activityItems);
	let stats = $state(initialState.stats);
	let selectedIp = $state<string | null>(null);
	let connection = $state<ConnectionState>('connecting');
	let isEstimatingOnline = $state(false);
	let estimateNotice = $state<{ kind: 'ok' | 'error'; message: string } | null>(null);

	const selectedDevice = $derived(devices.find((d) => d.ip === selectedIp) ?? null);
	const unnamedCount = $derived(devices.filter((d) => d.identity_status === 'unidentified').length);
	let dashboardState = createInitialDashboardState();

	function syncState(nextState: typeof dashboardState) {
		dashboardState = nextState;
		devices = nextState.devices;
		activityItems = nextState.activityItems;
		stats = nextState.stats;
		selectedIp = nextState.selectedIp;
	}

	async function hydrate() {
		const payload = await fetchDevices();
		syncState(applyDevicesPayload(dashboardState, payload));
	}

	function patchRenamed(mac: string, name: string) {
		syncState(patchRenamedDevice(dashboardState, mac, name));
	}

	function selectDevice(ip: string) {
		selectedIp = ip;
	}

	async function estimateOnline() {
		isEstimatingOnline = true;
		estimateNotice = null;
		try {
			const result = await estimateOnlineDevices('scanner');
			const estimated = result.estimated_count;
			const skipped = result.skipped_count;
			estimateNotice = {
				kind: 'ok',
				message: `${estimated} estimated, ${skipped} skipped`
			};
			await hydrate();
		} catch (err) {
			estimateNotice = {
				kind: 'error',
				message: err instanceof Error ? err.message : 'Estimate failed'
			};
		} finally {
			isEstimatingOnline = false;
		}
	}

	let feed: LiveDeviceFeed | null = null;

	$effect(() => {
		const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
		feed = new LiveDeviceFeed({
			wsUrl: `${proto}//${window.location.host}/ws`,
			fetchState: async () => {
				await hydrate();
			},
			onPayload: (payload) => {
				syncState(applyDevicesPayload(dashboardState, payload));
			},
			onConnectionChange: (next) => {
				connection = next;
			}
		});
		feed.start();

		return () => {
			feed?.stop();
			feed = null;
		};
	});
</script>

<RadarBackdrop />

<div class="shell">
	<TopBar
		{stats}
		{connection}
		onEstimateOnline={estimateOnline}
		{isEstimatingOnline}
		{estimateNotice}
	/>

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
