export function randomIP() {
  return `192.168.1.${Math.floor(Math.random() * 254)+1}`;
}

export function randomStatus() {
  return Math.random() < 0.5 ? 'online' : 'offline';
}

export function randomHostname() {
  const names = ['printer', 'laptop', 'phone', 'camera', 'tv'];
  return names[Math.floor(Math.random() * names.length)] + '-' + Math.floor(Math.random() * 100);
}
