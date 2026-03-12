import { serve } from "bun";
import { initDatabase } from "./database.ts";

const db = initDatabase("scanner.db");

const modules = new Map<string, WebSocket>();

serve({
  port: 3000,
  fetch(req, server) {
    const upgraded = server.upgrade(req);
    if (!upgraded) {
      return new Response("this is a websocket server", { status: 200 });
    }
  },
  websocket: {
    open(ws) {
      console.log("[server] new connection");
    },
    message(ws, raw) {
      const msg = JSON.parse(raw as string);
      console.log("[server] received:", msg);

      if (msg.type === "hello") {
        modules.set(msg.deviceId, ws);
        console.log(`[server] module registered: ${msg.deviceId}`);
        console.log(`[server] connected modules: ${[...modules.keys()]}`);
      }

      if (msg.type === "scan_result") {
        console.log(`[server] scan result from ${msg.deviceId}:`);
        for (const host of msg.data) {
          console.log(`  ${host.ip} | ${host.status} | ${host.hostname}`);
        }
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
