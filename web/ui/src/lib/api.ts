import type { Device, DevicesResponse } from '$lib/types';

export async function fetchDevices(): Promise<DevicesResponse> {
	const res = await fetch('/api/devices');
	if (!res.ok) {
		throw new Error(`Failed to fetch devices: ${res.status}`);
	}
	return (await res.json()) as DevicesResponse;
}

export async function saveDeviceName(mac: string, name: string): Promise<void> {
	const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/name`, {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ name })
	});

	if (!res.ok) {
		let detail = 'Failed to save name';
		try {
			const data = (await res.json()) as { detail?: string };
			detail = data.detail ?? detail;
		} catch {
			// ignore JSON parse errors
		}
		throw new Error(detail);
	}
}

export function normalizeSources(device: Device): string[] {
	if (Array.isArray(device.sources)) {
		return device.sources;
	}
	if (typeof device.sources === 'string' && device.sources.trim()) {
		return device.sources.split('+');
	}
	if (typeof device.source === 'string' && device.source.trim()) {
		return device.source.split('+');
	}
	return [];
}
