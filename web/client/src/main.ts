import { initMap, renderMap, initMapDraggable } from './map.ts';
import { rooms } from './rooms.ts';
import { fetchDevices } from './api.ts';
import { renderDevices } from './devices.ts';
import type { Device, DeviceAssignment, Room } from './types.ts';

let devices: Device[] = [];
let assignments: DeviceAssignment[] = [];
let canvasState: ReturnType<typeof initMap>;
let hoveredRoom: Room | null = null;

function handleDrop(deviceIp: string, roomId: string, x: number, y: number) {
  assignments = assignments.filter(a => a.deviceIp !== deviceIp);
  assignments.push({ deviceIp, roomId, x, y });
  render();
}

function render() {
  const width = canvasState.canvas.width / window.devicePixelRatio;
  const height = canvasState.canvas.height / window.devicePixelRatio;
  renderMap(canvasState, rooms, assignments, devices, width, height, hoveredRoom);
}

document.addEventListener('DOMContentLoaded', async () => {
  devices = await fetchDevices();
  renderDevices('devices-panel', devices);

  canvasState = initMap();
  initMapDraggable(canvasState, rooms, handleDrop);
  render();

  window.addEventListener('resize', () => {
    canvasState = initMap();
    initMapDraggable(canvasState, rooms, handleDrop);
    render();
  });
});
