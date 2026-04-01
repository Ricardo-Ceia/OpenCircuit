<script lang="ts">
	type Props = {
		count: number;
	};

	let { count }: Props = $props();
</script>

{#if count > 0}
	<div class="hint panel panel-warning">
		<div class="tag">Action needed</div>
		<div class="text">
			{count} unnamed device{count > 1 ? 's' : ''} waiting for labels. Open a card and assign a human name.
		</div>
	</div>
{/if}

<style>
	.hint {
		display: grid;
		grid-template-columns: auto 1fr;
		align-items: center;
		gap: 0.8rem;
		padding: 0.7rem 0.9rem;
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
