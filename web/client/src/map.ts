import type { Room, Device, DeviceAssignment, CanvasState } from './types.ts';

export function initMap(): CanvasState {
  const canvas = document.getElementById('map') as HTMLCanvasElement;
  const ctx = canvas.getContext('2d')!;

  const dpr = window.devicePixelRatio || 1;
  const width = window.innerWidth || 800;
  const height = window.innerHeight || 600;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.scale(dpr, dpr);

  return { ctx, canvas };
}

function isPointInRoom(x: number, y: number, room: Room, width: number, height: number): boolean {
  const points = room.points.map(p => ({ x: p.x * width, y: p.y * height }));
  let inside = false;

  for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
    const pi = points[i];
    const pj = points[j];
    if (!pi || !pj) continue;
    const xi = pi.x, yi = pi.y;
    const xj = pj.x, yj = pj.y;

    const intersect = ((yi > y) !== (yj > y)) &&
      (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
    if (intersect) inside = !inside;
  }

  return inside;
}

export function findRoomAtPoint(x: number, y: number, rooms: Room[], width: number, height: number): Room | null {
  for (const room of rooms) {
    if (isPointInRoom(x, y, room, width, height)) {
      return room;
    }
  }
  return null;
}

export function drawRoom(ctx: CanvasRenderingContext2D, room: Room, width: number, height: number): void {
  ctx.beginPath();

  const firstPoint = room.points[0];
  if (!firstPoint) return;

  ctx.moveTo(firstPoint.x * width, firstPoint.y * height);

  for (let i = 1; i < room.points.length; i++) {
    const point = room.points[i];
    if (!point) return;
    ctx.lineTo(point.x * width, point.y * height);
  }

  ctx.closePath();
  ctx.fillStyle = room.color;
  ctx.fill();
  ctx.strokeStyle = '#333333';
  ctx.lineWidth = 2;
  ctx.stroke();

  const centerX = room.points.reduce((sum, p) => sum + p.x, 0) / room.points.length * width;
  const centerY = room.points.reduce((sum, p) => sum + p.y, 0) / room.points.length * height;

  ctx.fillStyle = '#333333';
  ctx.font = '14px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(room.name, centerX, centerY);
}

function drawDeviceOnMap(
  ctx: CanvasRenderingContext2D,
  device: Device,
  assignment: DeviceAssignment,
  width: number,
  height: number
): void {
  const x = assignment.x * width;
  const y = assignment.y * height;

  ctx.beginPath();
  ctx.arc(x, y, 12, 0, Math.PI * 2);
  ctx.fillStyle = device.status === 'up' ? '#4ade80' : '#fbbf24';
  ctx.fill();
  ctx.strokeStyle = '#333';
  ctx.lineWidth = 2;
  ctx.stroke();

  ctx.fillStyle = '#333';
  ctx.font = '10px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(device.hostname.substring(0, 8), x, y);
}

export function renderMap(
  state: CanvasState,
  rooms: Room[],
  assignments: DeviceAssignment[],
  devices: Device[],
  width: number,
  height: number,
  hoveredRoom: Room | null = null
): void {
  const { ctx } = state;

  ctx.clearRect(0, 0, width, height);

  for (const room of rooms) {
    drawRoom(ctx, room, width, height);

    if (hoveredRoom && room.name === hoveredRoom.name) {
      ctx.beginPath();
      const firstPoint = room.points[0];
      if (firstPoint) {
        ctx.moveTo(firstPoint.x * width, firstPoint.y * height);
        for (let i = 1; i < room.points.length; i++) {
          const point = room.points[i];
          if (point) {
            ctx.lineTo(point.x * width, point.y * height);
          }
        }
        ctx.closePath();
        ctx.fillStyle = 'rgba(255, 255, 0, 0.4)';
        ctx.fill();
      }
    }
  }

  for (const assignment of assignments) {
    const device = devices.find(d => d.ip === assignment.deviceIp);
    if (device) {
      drawDeviceOnMap(ctx, device, assignment, width, height);
    }
  }
}

export function initMapDraggable(
  state: CanvasState,
  rooms: Room[],
  onDrop: (deviceIp: string, roomId: string, x: number, y: number) => void,
  onHover: (room: Room | null) => void
): void {
  const { canvas } = state;

  let hoveredRoom: Room | null = null;

  canvas.addEventListener('dragover', (e) => {
    e.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const width = rect.width;
    const height = rect.height;
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const newHoveredRoom = findRoomAtPoint(x, y, rooms, width, height);

    if (newHoveredRoom?.name !== hoveredRoom?.name) {
      hoveredRoom = newHoveredRoom;
      onHover(hoveredRoom);
    }

    canvas.style.cursor = hoveredRoom ? 'copy' : 'not-allowed';
  });

  canvas.addEventListener('dragleave', (e) => {
    const rect = canvas.getBoundingClientRect();
    if (e.clientX < rect.left || e.clientX > rect.right ||
        e.clientY < rect.top || e.clientY > rect.bottom) {
      hoveredRoom = null;
      onHover(null);
      canvas.style.cursor = 'default';
    }
  });

  canvas.addEventListener('drop', (e) => {
    e.preventDefault();
    const deviceIp = e.dataTransfer?.getData('text/plain');
    if (!deviceIp || !hoveredRoom) return;

    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;

    onDrop(deviceIp, hoveredRoom.name, x, y);
    hoveredRoom = null;
    onHover(null);
    canvas.style.cursor = 'default';
  });
}
