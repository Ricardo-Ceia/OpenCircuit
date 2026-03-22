export type Point = { x: number; y: number };

export type Room = {
  name: string;
  color: string;
  points: Point[];
};

export type Device = {
  ip: string;
  hostname: string;
  status: 'up' | 'recently_seen' | 'down';
  ports: number[];
};

export type DeviceAssignment = {
  deviceIp: string;
  roomId: string;
  x: number;
  y: number;
};

export type CanvasState = {
  ctx: CanvasRenderingContext2D;
  canvas: HTMLCanvasElement;
};
