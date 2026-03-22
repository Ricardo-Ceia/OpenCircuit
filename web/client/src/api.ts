import type {Device} from './types.ts'

export async function fetchDevices(): Promise<Device[]> {
  return [
    { ip: "192.168.1.1", hostname: "Router", status: "up", ports: [80, 443, 53] },
    { ip: "192.168.1.10", hostname: "Laptop-Ricardo", status: "up", ports: [22, 3000] },
    { ip: "192.168.1.15", hostname: "iPhone", status: "recently_seen", ports: [] },
    { ip: "192.168.1.20", hostname: "Smart-TV", status: "up", ports: [8008, 8443] },
    { ip: "192.168.1.25", hostname: "Desktop", status: "up", ports: [22, 80, 443] },
    { ip: "192.168.1.30", hostname: "Guest-Phone", status: "down", ports: [] },
    { ip: "192.168.1.35", hostname: "Smart-Speaker", status: "up", ports: [80] },
  ];
}
