import { initMap, renderMap, initMapDraggable, findDeviceAtPoint } from './map.ts';
import { rooms } from './rooms.ts';
import { fetchDevices } from './api.ts';
import { renderDevices } from './devices.ts';
import type { Device, DeviceAssignment, Room } from './types.ts';

let devices: Device[] = [];
let assignments: DeviceAssignment[] = [];
let canvasState: ReturnType<typeof initMap>;
let hoveredRoom: Room | null = null;
let selectedDeviceIp: string | null = null;
let resizeObserver: ResizeObserver | null = null;

function getAssignedRoomName(deviceIp: string): string {
  const assignment = assignments.find(a => a.deviceIp === deviceIp);
  return assignment ? assignment.roomId : 'Unassigned';
}

function renderDetailsPanel(): void {
  const container = document.getElementById('details-content');
  if (!container) return;

  if (!selectedDeviceIp) {
    container.innerHTML = 'Select a device from the list or map.';
    return;
  }

  const device = devices.find(d => d.ip === selectedDeviceIp);
  if (!device) {
    container.innerHTML = 'Device not found.';
    return;
  }

  const ports = device.ports.length > 0 ? device.ports.join(', ') : '-';
  const room = getAssignedRoomName(device.ip);

  container.innerHTML = `
    <div class="detail-row"><span class="detail-label">Hostname:</span><span class="detail-value">${device.hostname || '-'}</span></div>
    <div class="detail-row"><span class="detail-label">IP:</span><span class="detail-value">${device.ip}</span></div>
    <div class="detail-row"><span class="detail-label">Status:</span><span class="detail-value">${device.status}</span></div>
    <div class="detail-row"><span class="detail-label">Ports:</span><span class="detail-value">${ports}</span></div>
    <div class="detail-row"><span class="detail-label">Room:</span><span class="detail-value">${room}</span></div>
  `;
}

function selectDevice(deviceIp: string): void {
  selectedDeviceIp = deviceIp;
  render();
}

function onCanvasClick(e: MouseEvent): void {
  const rect = canvasState.canvas.getBoundingClientRect();
  const width = rect.width;
  const height = rect.height;
  const x = e.clientX - rect.left;
  const y = e.clientY - rect.top;

  const device = findDeviceAtPoint(x, y, assignments, devices, width, height);
  if (device) {
    selectedDeviceIp = device.ip;
    render();
  }
}

function bindCanvasInteractions(): void {
  initMapDraggable(canvasState, rooms, handleDrop, onHover);
  canvasState.canvas.onclick = onCanvasClick;
}

function reflowAndRender(): void {
  canvasState = initMap();
  bindCanvasInteractions();
  render();
}

function handleDrop(deviceIp: string, roomId: string, x: number, y: number) {
  assignments = assignments.filter(a => a.deviceIp !== deviceIp);
  assignments.push({ deviceIp, roomId, x, y });
  hoveredRoom = null;
  selectedDeviceIp = deviceIp;
  render();
}

function render() {
  const width = canvasState.canvas.width / window.devicePixelRatio;
  const height = canvasState.canvas.height / window.devicePixelRatio;
  renderMap(canvasState, rooms, assignments, devices, width, height, hoveredRoom, selectedDeviceIp);
  renderDevices('devices-panel', devices, selectedDeviceIp, selectDevice);
  renderDetailsPanel();
}

function onHover(room: Room | null) {
  hoveredRoom = room;
  render();
}

document.addEventListener('DOMContentLoaded', async () => {
  devices = await fetchDevices();

  reflowAndRender();

  const mapStage = document.getElementById('map-stage');
  if (mapStage) {
    resizeObserver = new ResizeObserver(() => {
      reflowAndRender();
    });
    resizeObserver.observe(mapStage);
  }

  window.addEventListener('resize', reflowAndRender);
});
