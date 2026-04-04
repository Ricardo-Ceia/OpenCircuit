import type { Device, DeviceStats, DevicesResponse } from '$lib/types';
import { relativeTime, sortDevices } from '$lib/utils';

export type ActivityItem = {
	id: string;
	label: string;
	status: string;
	time: string;
};

export type DashboardState = {
	devices: Device[];
	activityItems: ActivityItem[];
	stats: DeviceStats;
	selectedIp: string | null;
	lastPayloadStamp: string;
};

export const EMPTY_STATS: DeviceStats = {
	total: 0,
	online: 0,
	offline: 0,
	claimed: 0,
	verified: 0,
	identified: 0,
	unidentified: 0
};

function payloadStamp(payload: DevicesResponse): string {
	const parts = [
		String(payload.stats?.total ?? 0),
		String(payload.stats?.online ?? 0),
		String(payload.stats?.offline ?? 0),
		String(payload.stats?.unidentified ?? 0)
	];
	for (const device of payload.devices ?? []) {
		parts.push(
			`${device.ip}|${device.label}|${device.identity_status}|${device.status ?? ''}|${device.last_seen ?? ''}|${device.label_source ?? ''}`
		);
	}
	return parts.join('~');
}

function buildActivityItems(devices: Device[]): ActivityItem[] {
	return [...devices]
		.filter((device) => device.last_seen)
		.sort((a, b) => (b.last_seen ?? '').localeCompare(a.last_seen ?? ''))
		.slice(0, 8)
		.map((device) => ({
			id: device.ip,
			label: device.label,
			status: (device.status ?? 'offline') === 'online' ? 'seen online' : 'offline',
			time: relativeTime(device.last_seen)
		}));
}

function selectNextIp(selectedIp: string | null, devices: Device[]): string | null {
	if (devices.length === 0) {
		return null;
	}
	if (!selectedIp) {
		return devices[0].ip;
	}
	if (!devices.some((device) => device.ip === selectedIp)) {
		return devices[0].ip;
	}
	return selectedIp;
}

export function createInitialDashboardState(): DashboardState {
	return {
		devices: [],
		activityItems: [],
		stats: EMPTY_STATS,
		selectedIp: null,
		lastPayloadStamp: ''
	};
}

export function applyDevicesPayload(state: DashboardState, payload: DevicesResponse): DashboardState {
	const stamp = payloadStamp(payload);
	if (stamp === state.lastPayloadStamp) {
		return state;
	}

	const devices = sortDevices(payload.devices ?? []);

	return {
		devices,
		activityItems: buildActivityItems(devices),
		stats: payload.stats ?? state.stats,
		selectedIp: selectNextIp(state.selectedIp, devices),
		lastPayloadStamp: stamp
	};
}

export function patchRenamedDevice(state: DashboardState, mac: string, name: string): DashboardState {
	const normalizedMac = mac.toLowerCase();
	const updatedDevices = state.devices.map((device) => {
		if ((device.mac ?? '').toLowerCase() !== normalizedMac) {
			return device;
		}
		return {
			...device,
			label: name,
			label_source: 'known',
			identity_status: 'claimed' as const,
			label_authoritative: true
		};
	});

	const devices = sortDevices(updatedDevices);

	return {
		...state,
		devices,
		activityItems: buildActivityItems(devices),
		stats: {
			...state.stats,
			claimed: devices.filter((device) => device.identity_status === 'claimed').length,
			unidentified: devices.filter((device) => device.identity_status === 'unidentified').length
		},
		selectedIp: selectNextIp(state.selectedIp, devices)
	};
}
