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
}
