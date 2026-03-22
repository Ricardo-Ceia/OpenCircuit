import type { Device } from './types.ts';

export function renderDevices(
  devicePanelId: string,
  devices: Device[],
  selectedDeviceIp: string | null,
  onSelect: (deviceIp: string) => void
): void {
  const panel = document.getElementById(devicePanelId);
  if (!panel) return;

  panel.innerHTML = '<h2>Devices</h2>';

  for (const device of devices) {
    const div = document.createElement('div');
    div.className = `device-item${selectedDeviceIp === device.ip ? ' selected' : ''}`;
    div.draggable = true;
    div.dataset.ip = device.ip;

    const statusClass = `status-${device.status}`;
    const portCount = device.ports.length;

    div.innerHTML = `
      <div class="device-hostname">${device.hostname || '-'}</div>
      <div class="device-ip">${device.ip}</div>
      <div class="device-meta">
        <span class="${statusClass}">${device.status}</span>
        <span class="device-ports">${portCount} port${portCount !== 1 ? 's' : ''}</span>
      </div>
    `;

    div.addEventListener('dragstart', (e) => {
      if (e.dataTransfer) {
        e.dataTransfer.effectAllowed = 'copy';
        e.dataTransfer.setData('text/plain', device.ip);
      }
    });

    div.addEventListener('click', () => {
      onSelect(device.ip);
    });

    panel.appendChild(div);
  }
}
