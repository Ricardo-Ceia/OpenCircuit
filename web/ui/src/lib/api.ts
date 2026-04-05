import type { Device, DeviceStats, DevicesResponse, DeviceStatus, IdentityStatus } from '$lib/types';

export type BleSample = {
	device_key: string;
	rssi_dbm: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null;
}

function asString(value: unknown, fallback = ''): string {
	return typeof value === 'string' ? value : fallback;
}

function asNullableString(value: unknown): string | null | undefined {
	if (value === null || value === undefined) {
		return value;
	}
	return typeof value === 'string' ? value : undefined;
}

function asIdentityStatus(value: unknown): IdentityStatus {
	if (value === 'claimed' || value === 'verified' || value === 'identified' || value === 'unidentified') {
		return value;
	}
	return 'unidentified';
}

function asDeviceStatus(value: unknown): DeviceStatus | undefined {
	if (value === 'online' || value === 'offline') {
		return value;
	}
	return undefined;
}

function asStringArray(value: unknown): string[] | undefined {
	if (!Array.isArray(value)) {
		return undefined;
	}
	const filtered = value.filter((entry): entry is string => typeof entry === 'string');
	return filtered.length > 0 ? filtered : [];
}

function parseDevice(raw: unknown): Device | null {
	if (!isRecord(raw)) {
		return null;
	}
	const ip = asString(raw.ip);
	const label = asString(raw.label);
	if (!ip || !label) {
		return null;
	}

	return {
		ip,
		label,
		label_source: asString(raw.label_source) || undefined,
		label_authoritative: typeof raw.label_authoritative === 'boolean' ? raw.label_authoritative : undefined,
		identity_status: asIdentityStatus(raw.identity_status),
		hostname: asString(raw.hostname) || undefined,
		mac: asString(raw.mac) || undefined,
		vendor: asNullableString(raw.vendor),
		sources:
			typeof raw.sources === 'string' || Array.isArray(raw.sources) ? (raw.sources as string | string[]) : undefined,
		source: asString(raw.source) || undefined,
		services: asStringArray(raw.services),
		fingerprint: isRecord(raw.fingerprint) ? raw.fingerprint : undefined,
		status: asDeviceStatus(raw.status),
		first_seen: asString(raw.first_seen) || undefined,
		last_seen: asString(raw.last_seen) || undefined,
		location_hint: asString(raw.location_hint) || undefined,
		location_confidence:
			typeof raw.location_confidence === 'number' && Number.isFinite(raw.location_confidence)
				? raw.location_confidence
				: undefined,
		estimated_via: asString(raw.estimated_via) || undefined
	};
}

function parseStats(raw: unknown): DeviceStats {
	if (!isRecord(raw)) {
		return {
			total: 0,
			online: 0,
			offline: 0,
			claimed: 0,
			verified: 0,
			identified: 0,
			unidentified: 0
		};
	}
	const toNumber = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0);
	return {
		total: toNumber(raw.total),
		online: toNumber(raw.online),
		offline: toNumber(raw.offline),
		claimed: toNumber(raw.claimed),
		verified: toNumber(raw.verified),
		identified: toNumber(raw.identified),
		unidentified: toNumber(raw.unidentified)
	};
}

function parseDevicesResponse(raw: unknown): DevicesResponse {
	if (!isRecord(raw) || !Array.isArray(raw.devices)) {
		throw new Error('Invalid devices payload');
	}

	const devices = raw.devices
		.map((entry) => parseDevice(entry))
		.filter((entry): entry is Device => entry !== null);

	return {
		devices,
		stats: parseStats(raw.stats),
		last_scan: asString(raw.last_scan),
		type: raw.type === 'full_state' || raw.type === 'scan_update' ? raw.type : undefined
	};
}

export async function fetchDevices(): Promise<DevicesResponse> {
	const res = await fetch('/api/devices');
	if (!res.ok) {
		throw new Error(`Failed to fetch devices: ${res.status}`);
	}
	const payload = (await res.json()) as unknown;
	return parseDevicesResponse(payload);
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

export async function fetchLocationRooms(): Promise<string[]> {
	const res = await fetch('/api/location/rooms');
	if (!res.ok) {
		throw new Error(`Failed to fetch location rooms: ${res.status}`);
	}
	const payload = (await res.json()) as { rooms?: unknown };
	if (!Array.isArray(payload.rooms)) {
		return [];
	}
	return payload.rooms.filter((room): room is string => typeof room === 'string' && room.trim().length > 0);
}

export async function saveLocationRooms(rooms: string[]): Promise<string[]> {
	const res = await fetch('/api/location/rooms', {
		method: 'PUT',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({ rooms })
	});
	if (!res.ok) {
		throw new Error(`Failed to save location rooms: ${res.status}`);
	}
	const payload = (await res.json()) as { rooms?: unknown };
	if (!Array.isArray(payload.rooms)) {
		return [];
	}
	return payload.rooms.filter((room): room is string => typeof room === 'string' && room.trim().length > 0);
}

export async function submitBleCalibration(
	params: {
		room: string;
		sensorPosition: string;
		samples: BleSample[];
	}
): Promise<void> {
	const res = await fetch('/api/location/calibration', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			room: params.room,
			sensor_position: params.sensorPosition,
			samples: params.samples
		})
	});
	if (!res.ok) {
		let detail = `Calibration failed: ${res.status}`;
		try {
			const payload = (await res.json()) as { detail?: string };
			if (payload.detail) {
				detail = payload.detail;
			}
		} catch {
			// ignore parse error
		}
		throw new Error(detail);
	}
}

export async function submitBleEstimate(
	params: {
		sensorPosition: string;
		samples: BleSample[];
	}
): Promise<void> {
	const res = await fetch('/api/location/estimate', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json'
		},
		body: JSON.stringify({
			sensor_position: params.sensorPosition,
			samples: params.samples
		})
	});
	if (!res.ok) {
		let detail = `Estimate failed: ${res.status}`;
		try {
			const payload = (await res.json()) as { detail?: string };
			if (payload.detail) {
				detail = payload.detail;
			}
		} catch {
			// ignore parse error
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
