import type { DevicesResponse } from '$lib/types';

export type ConnectionState = 'connecting' | 'connected' | 'disconnected';

type FeedConfig = {
	wsUrl: string;
	fallbackPollMs?: number;
	heartbeatMs?: number;
	reconnectMs?: number;
	fetchState: () => Promise<void>;
	onPayload: (payload: DevicesResponse) => void;
	onConnectionChange: (state: ConnectionState) => void;
};

const DEFAULT_FALLBACK_POLL_MS = 10_000;
const DEFAULT_WS_HEARTBEAT_MS = 20_000;
const DEFAULT_WS_RECONNECT_MS = 2_200;

function isPayloadLike(value: unknown): value is DevicesResponse {
	if (!value || typeof value !== 'object') {
		return false;
	}
	const payload = value as Partial<DevicesResponse>;
	return Array.isArray(payload.devices) && typeof payload.last_scan === 'string';
}

export class LiveDeviceFeed {
	private readonly wsUrl: string;
	private readonly fallbackPollMs: number;
	private readonly heartbeatMs: number;
	private readonly reconnectMs: number;
	private readonly fetchState: () => Promise<void>;
	private readonly onPayload: (payload: DevicesResponse) => void;
	private readonly onConnectionChange: (state: ConnectionState) => void;

	private ws: WebSocket | null = null;
	private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
	private pollTimer: ReturnType<typeof setInterval> | null = null;
	private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
	private queuedPayload: DevicesResponse | null = null;
	private queuedFrame = 0;
	private hydrateInFlight = false;
	private shouldReconnect = false;

	constructor(config: FeedConfig) {
		this.wsUrl = config.wsUrl;
		this.fallbackPollMs = config.fallbackPollMs ?? DEFAULT_FALLBACK_POLL_MS;
		this.heartbeatMs = config.heartbeatMs ?? DEFAULT_WS_HEARTBEAT_MS;
		this.reconnectMs = config.reconnectMs ?? DEFAULT_WS_RECONNECT_MS;
		this.fetchState = config.fetchState;
		this.onPayload = config.onPayload;
		this.onConnectionChange = config.onConnectionChange;
	}

	start() {
		if (this.shouldReconnect) {
			return;
		}
		this.shouldReconnect = true;
		this.onConnectionChange('connecting');
		void this.hydrate();
		this.startFallbackPolling();
		this.connectWs();
	}

	stop() {
		this.shouldReconnect = false;
		this.clearReconnectTimer();
		this.clearHeartbeatTimer();

		if (this.pollTimer) {
			clearInterval(this.pollTimer);
			this.pollTimer = null;
		}

		if (this.queuedFrame) {
			cancelAnimationFrame(this.queuedFrame);
			this.queuedFrame = 0;
		}

		this.queuedPayload = null;

		if (this.ws) {
			const socket = this.ws;
			this.ws = null;
			socket.close();
		}
	}

	private clearReconnectTimer() {
		if (this.reconnectTimer) {
			clearTimeout(this.reconnectTimer);
			this.reconnectTimer = null;
		}
	}

	private clearHeartbeatTimer() {
		if (this.heartbeatTimer) {
			clearInterval(this.heartbeatTimer);
			this.heartbeatTimer = null;
		}
	}

	private startHeartbeat() {
		this.clearHeartbeatTimer();
		this.heartbeatTimer = setInterval(() => {
			if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
				return;
			}
			try {
				this.ws.send('ping');
			} catch {
				// socket lifecycle handlers recover
			}
		}, this.heartbeatMs);
	}

	private startFallbackPolling() {
		if (this.pollTimer) {
			return;
		}
		this.pollTimer = setInterval(() => {
			void this.hydrate();
		}, this.fallbackPollMs);
	}

	private queueStateApply(payload: DevicesResponse) {
		this.queuedPayload = payload;
		if (this.queuedFrame) {
			return;
		}

		this.queuedFrame = requestAnimationFrame(() => {
			this.queuedFrame = 0;
			if (!this.queuedPayload) {
				return;
			}
			const next = this.queuedPayload;
			this.queuedPayload = null;
			this.onPayload(next);
		});
	}

	private async hydrate() {
		if (this.hydrateInFlight) {
			return;
		}

		this.hydrateInFlight = true;
		try {
			await this.fetchState();
		} catch {
			if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
				this.onConnectionChange('disconnected');
			}
		} finally {
			this.hydrateInFlight = false;
		}
	}

	private connectWs() {
		const nextWs = new WebSocket(this.wsUrl);
		this.ws = nextWs;

		nextWs.onopen = () => {
			if (this.ws !== nextWs) {
				return;
			}
			this.onConnectionChange('connected');
			this.clearReconnectTimer();
			this.startHeartbeat();
			void this.hydrate();
		};

		nextWs.onmessage = (event) => {
			if (this.ws !== nextWs) {
				return;
			}
			try {
				const payload = JSON.parse(event.data) as unknown;
				if (!isPayloadLike(payload)) {
					return;
				}
				this.queueStateApply(payload);
			} catch {
				// ignore malformed frames
			}
		};

		nextWs.onclose = () => {
			if (this.ws !== nextWs) {
				return;
			}
			this.ws = null;
			this.clearHeartbeatTimer();
			this.onConnectionChange('disconnected');
			void this.hydrate();

			if (!this.shouldReconnect) {
				return;
			}
			this.clearReconnectTimer();
			this.reconnectTimer = setTimeout(() => {
				if (!this.shouldReconnect) {
					return;
				}
				this.onConnectionChange('connecting');
				this.connectWs();
			}, this.reconnectMs);
		};

		nextWs.onerror = () => {
			if (this.ws !== nextWs) {
				return;
			}
			this.onConnectionChange('disconnected');
		};
	}
}
