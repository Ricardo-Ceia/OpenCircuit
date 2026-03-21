export function initMap(canvasId: string,width: number,height :number,cellSize :number): {ctx: CanvasRenderingContext2D, map: number[][]} | null {
  var canvas = document.getElementById(canvasId) as HTMLCanvasElement;
  if(!canvas) return null;
  
  const ctx = canvas.getContext('2d');
  if(!ctx) return null;
  
  const dpr = window.devicePixelRatio || 1;
  canvas.width = width * cellSize * dpr;
  canvas.height = height * cellSize * dpr;
  canvas.style.width = `${width * cellSize}px`;
  canvas.style.height = `${height * cellSize}px`;

  ctx.scale(dpr, dpr);

  const map: number[][] = Array.from({ length: height }, () => Array(width).fill(1));
  return {ctx,map}
}
