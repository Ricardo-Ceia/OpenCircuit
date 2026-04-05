export type IdentityStatus = 'claimed' | 'verified' | 'identified' | 'unidentified';

export type DeviceStatus = 'online' | 'offline';

export type Fingerprint = {
	manufacturer?: string | null;
	model?: string | null;
	friendly_name?: string | null;
	device_type?: string | null;
	model_number?: string | null;
	[key: string]: unknown;
};

export type Device = {
	ip: string;
	label: string;
	label_source?: string;
	label_authoritative?: boolean;
	identity_status: IdentityStatus;
	hostname?: string;
	mac?: string;
	vendor?: string | null;
	sources?: string[] | string;
	source?: string;
	services?: string[];
	fingerprint?: Fingerprint;
	status?: DeviceStatus;
	first_seen?: string;
	last_seen?: string;
	location_hint?: string;
	location_confidence?: number;
	distance_meters?: number;
	rssi_dbm?: number;
	estimated_via?: string;
};

export type DeviceStats = {
	total: number;
	online: number;
	offline: number;
	claimed: number;
	verified: number;
	identified: number;
	unidentified: number;
};

export type DevicesResponse = {
	devices: Device[];
	stats: DeviceStats;
	last_scan: string;
	type?: 'full_state' | 'scan_update';
};
