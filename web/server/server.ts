import { serve } from "bun";
import { Scanner } from "./database.ts";
import {getScansHandler,getDevicesHandler} from "./routes.ts";


function getDeviceIdFromUrl(url: string): string | null{
  const parts = url.split("/");
  const deviceId = parts[2];
  return deviceId && /^[a-zA-Z0-9-_]+$/.test(deviceId) ? deviceId : null;
}


const scanner = new Scanner("scanner.db");
const modules = new Map<string, WebSocket>();

serve({
  port: 3000,
  routes: {
    "/devices/:deviceId": (req) => {
      const url = new URL(req.url).toString();
      const deviceId = getDeviceIdFromUrl(url)
      if(!deviceId)return;
      return getDevicesHandler(scanner,deviceId);      
    },
    "/scans/:deviceId": (req) => {
      const url = new URL(req.url).toString();
      const deviceId = getDeviceIdFromUrl(url);
      if(!deviceId)return;
      return getScansHandler(scanner,deviceId);  
    },
  },
  fetch(req, server) {
    const upgraded = server.upgrade(req);
    if (!upgraded) {
      return new Response("not found", { status: 404 });
    }
  },
  websocket: {
    open(ws) {
      console.log("[server] new connection");
    },
    message(ws, raw) {
      const msg = JSON.parse(raw as string);
      console.log("[server] received:", msg.type);

      if (msg.type === "hello") {
        modules.set(msg.deviceId, ws);
        console.log(`[server] module registered: ${msg.deviceId}`);
        console.log(`[server] connected modules: ${[...modules.keys()]}`);
      }

      if (msg.type === "scan_result") {
        console.log(`[server] scan result from ${msg.deviceId} — ${msg.data.length} hosts`);
        scanner.insertScan(msg.deviceId, msg.data);
        scanner.upsertDevices(msg.deviceId, msg.data);
        scanner.cleanOldScans(msg.deviceId);
        console.log(`[server] scan persisted for ${msg.deviceId}`);
      }
    },
    close(ws) {
      for (const [deviceId, socket] of modules.entries()) {
        if (socket === ws) {
          modules.delete(deviceId);
          console.log(`[server] module disconnected: ${deviceId}`);
        }
      }
    },
  },
});

console.log("[server] listening on ws://localhost:3000");
