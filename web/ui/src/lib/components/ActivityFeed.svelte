<script lang="ts">
	import type { Device } from '$lib/types';
	import { relativeTime } from '$lib/utils';

	type Props = {
		devices: Device[];
	};

	let { devices }: Props = $props();

	const items = $derived(
		[...devices]
			.filter((d) => d.last_seen)
			.sort((a, b) => (b.last_seen ?? '').localeCompare(a.last_seen ?? ''))
			.slice(0, 8)
			.map((d) => {
				const status = (d.status ?? 'offline') === 'online' ? 'seen online' : 'offline';
				return {
					id: d.ip,
					label: d.label,
					status,
					time: relativeTime(d.last_seen)
				};
			})
	);
</script>

<section class="panel feed">
	<div class="head">
		<div class="title">Recent Activity</div>
		<div class="sub">Last 8 contact updates</div>
	</div>

	{#if items.length === 0}
		<div class="empty">No activity yet</div>
	{:else}
		<ul>
			{#each items as event (event.id)}
				<li>
					<div class="event-label">{event.label}</div>
					<div class="event-meta">{event.status} · {event.time}</div>
				</li>
			{/each}
		</ul>
	{/if}
</section>

<style>
	.feed {
		display: grid;
		gap: 0.65rem;
		padding: 0.9rem;
		min-block-size: 0;
	}

	.head {
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
		letter-spacing: 0.11em;
		text-transform: uppercase;
		color: var(--tone-muted);
	}

	.empty {
		font-size: 0.68rem;
		color: var(--tone-muted-bright);
		padding: 0.8rem 0.2rem;
	}

	ul {
		list-style: none;
		display: grid;
		gap: 0.38rem;
		min-block-size: 0;
		overflow: auto;
		scrollbar-gutter: stable;
	}

	li {
		padding: 0.45rem 0.52rem;
		border: 1px solid var(--edge-soft);
		border-radius: 0.35rem;
		background: color-mix(in oklab, var(--panel-alt) 84%, black);
	}

	.event-label {
		font-size: 0.71rem;
		color: var(--tone-text-bright);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.event-meta {
		margin-top: 0.22rem;
		font-size: 0.61rem;
		letter-spacing: 0.07em;
		text-transform: uppercase;
		color: var(--tone-muted);
	}
</style>
