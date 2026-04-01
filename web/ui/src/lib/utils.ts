import type { Device, DeviceStatus, IdentityStatus } from '$lib/types';

export const identityOrder: Record<IdentityStatus, number> = {
	claimed: 0,
	verified: 1,
	identified: 2,
	unidentified: 3
};

export const statusOrder: Record<DeviceStatus, number> = {
	online: 0,
	offline: 1
};

export function deviceClue(device: Device): string {
	const fp = device.fingerprint ?? {};
	if (fp.manufacturer && fp.model) {
		return `${fp.manufacturer} ${fp.model}`;
	}
	if (fp.manufacturer) {
		return `${fp.manufacturer}`;
	}
	if (device.vendor) {
		return device.vendor;
	}
	if (device.hostname && device.hostname !== 'unknown') {
		return device.hostname;
	}
	return '';
}

export function sortDevices(devices: Device[]): Device[] {
	return [...devices].sort((a, b) => {
		const identityDiff =
			(identityOrder[a.identity_status] ?? 9) - (identityOrder[b.identity_status] ?? 9);
		if (identityDiff !== 0) {
			return identityDiff;
		}
		const statusA = (a.status ?? 'offline') as DeviceStatus;
		const statusB = (b.status ?? 'offline') as DeviceStatus;
		const statusDiff = (statusOrder[statusA] ?? 9) - (statusOrder[statusB] ?? 9);
		if (statusDiff !== 0) {
			return statusDiff;
		}
		return (a.first_seen ?? '').localeCompare(b.first_seen ?? '');
	});
}

export function relativeTime(ts?: string): string {
	if (!ts) {
		return 'unknown';
	}
	const date = new Date(ts);
	const diff = Date.now() - date.getTime();
	if (diff < 60_000) {
		return 'now';
	}
	if (diff < 3_600_000) {
		return `${Math.floor(diff / 60_000)} min ago`;
	}
	if (diff < 86_400_000) {
		return `${Math.floor(diff / 3_600_000)}h ago`;
	}
	return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function isNamable(device: Device): boolean {
	return Boolean(device.mac && device.mac !== 'unknown');
}

export function isOnline(device: Device): boolean {
	return (device.status ?? 'offline') === 'online';
}
