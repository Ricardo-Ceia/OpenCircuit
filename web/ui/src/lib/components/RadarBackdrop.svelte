<div class="backdrop" aria-hidden="true">
	<div class="mesh mesh-a"></div>
	<div class="mesh mesh-b"></div>
	<div class="grain"></div>
</div>

<style>
	.backdrop {
		position: fixed;
		inset: 0;
		pointer-events: none;
		overflow: hidden;
		z-index: -1;
	}

	.mesh {
		position: absolute;
		filter: blur(54px);
		opacity: 0.35;
	}

	.mesh-a {
		inline-size: min(46vw, 36rem);
		block-size: min(46vw, 36rem);
		top: -14%;
		left: -9%;
		background: radial-gradient(circle, color-mix(in oklab, var(--tone-online) 58%, transparent), transparent 68%);
		animation: driftA 16s ease-in-out infinite alternate;
	}

	.mesh-b {
		inline-size: min(50vw, 39rem);
		block-size: min(50vw, 39rem);
		bottom: -20%;
		right: -12%;
		background: radial-gradient(circle, color-mix(in oklab, var(--tone-cyan) 42%, transparent), transparent 70%);
		animation: driftB 19s ease-in-out infinite alternate;
	}

	.grain {
		position: absolute;
		inset: 0;
		background-image:
			radial-gradient(circle at 1px 1px, rgba(255, 255, 255, 0.04) 1px, transparent 0),
			repeating-linear-gradient(0deg, transparent 0, transparent 3px, rgba(0, 0, 0, 0.07) 4px);
		background-size: 3px 3px, 100% 6px;
		opacity: 0.27;
	}

	@keyframes driftA {
		from {
			transform: translate3d(0, 0, 0) scale(1);
		}
		to {
			transform: translate3d(4%, -3%, 0) scale(1.08);
		}
	}

	@keyframes driftB {
		from {
			transform: translate3d(0, 0, 0) scale(1);
		}
		to {
			transform: translate3d(-4%, 4%, 0) scale(1.09);
		}
	}
</style>
