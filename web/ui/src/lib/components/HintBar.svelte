<script lang="ts">
	type Props = {
		count: number;
	};

	let { count }: Props = $props();
</script>

<div class={`hint panel panel-warning ${count > 0 ? 'visible' : 'hidden'}`} aria-live="polite">
	<div class="tag">Action needed</div>
	<div class="text">
		{#if count > 0}
			{count} unnamed device{count > 1 ? 's' : ''} waiting for labels. Open a card and assign a human name.
		{:else}
			All active devices are named.
		{/if}
	</div>
</div>

<style>
	.hint {
		display: grid;
		grid-template-columns: auto 1fr;
		align-items: center;
		gap: 0.8rem;
		padding: 0.7rem 0.9rem;
		min-block-size: 3.2rem;
		transition: opacity 180ms ease;
	}

	.hint.hidden {
		opacity: 0.44;
		border-color: var(--edge-soft);
		box-shadow: none;
	}

	.hint.hidden .tag {
		color: var(--tone-muted);
		border-color: var(--edge-soft);
		background: transparent;
	}

	.hint.hidden .text {
		color: var(--tone-muted);
	}

	.tag {
		font-size: 0.58rem;
		letter-spacing: 0.12em;
		text-transform: uppercase;
		padding: 0.2rem 0.42rem;
		border: 1px solid color-mix(in oklab, var(--tone-warning) 40%, transparent);
		border-radius: 0.28rem;
		color: var(--tone-warning);
		background: color-mix(in oklab, var(--tone-warning) 8%, transparent);
	}

	.text {
		font-size: 0.69rem;
		line-height: 1.45;
		color: var(--tone-warning-soft);
		letter-spacing: 0.03em;
	}
</style>
