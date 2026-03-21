import type {Room} from './types.ts'

export function initMap(canvasId: string): { ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement } | null {
  const canvas = document.getElementById(canvasId) as HTMLCanvasElement;
  if (!canvas) return null;

  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  const dpr = window.devicePixelRatio || 1;
  const width = window.innerWidth;
  const height = window.innerHeight;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;

  ctx.scale(dpr, dpr);

  return { ctx, canvas };
}

export function drawRoom(ctx: CanvasRenderingContext2D, room: Room, width: number, height: number): void{
  ctx.beginPath();

  const firstPoint = room.points[0];
  if(!firstPoint)return;

  ctx.moveTo(firstPoint.x * width, firstPoint.y * height);

  for (let i = 1; i < room.points.length; i++) {
    const point = room.points[i];
    if(!point)return;

    ctx.lineTo(point.x * width, point.y * height);
  }

  ctx.closePath();

  ctx.fillStyle = room.color;
  ctx.fill();

  ctx.strokeStyle = '#333333';
  ctx.lineWidth = 2;
  ctx.stroke();

  // draw room name in the center
  const centerX = room.points.reduce((sum, p) => sum + p.x, 0) / room.points.length * width;
  const centerY = room.points.reduce((sum, p) => sum + p.y, 0) / room.points.length * height;

  ctx.fillStyle = '#333333';
  ctx.font = '14px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(room.name, centerX, centerY);
}

