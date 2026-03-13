import {Scanner} from './database.ts';


export function getDevicesHandler(scanner: Scanner,deviceId: string) :Response{
  const devices = scanner.getDevices(deviceId);
  return new Response(JSON.stringify(devices), {
    headers: { "Content-Type": "application/json" },
  });
}

export function getScansHandler(scanner: Scanner,deviceId: string) :Response{
  const scans = scanner.getScans(deviceId) as any[];
  const parsedScans = scans.map(scan=>({
    ...scan,
    summary: JSON.parse(scan.summary),
    })
  );
  return new Response(JSON.stringify(parsedScans), {
    headers: { "Content-Type": "application/json" },
  });
}
