import * as randomData from "./random-data";

const SERVER_URL = "ws://localhost:3000";
const DEVICE_ID = "home-001";
const RECONNECT_DELAY_MS = 5000;

function connect() {
  console.log(`[module] connecting to ${SERVER_URL}...`);
  const ws = new WebSocket(SERVER_URL);

  ws.addEventListener("open", () => {
    console.log("[module] connected");

    ws.send(JSON.stringify({
      type: "hello",
      deviceId: DEVICE_ID,
    }));

    let scanInterval: Timer | null = null;
    
    if(scanInterval) clearInterval(scanInterval);
    setInterval(() => {
      ws.send(JSON.stringify({
        type: "scan_result",
        deviceId: DEVICE_ID,
        data: [
          {ip:randomData.randomIP(),status:randomData.randomStatus(),hostname:randomData.randomHostname()},
          {ip:randomData.randomIP(),status:randomData.randomStatus(),hostname:randomData.randomHostname()},
          {ip:randomData.randomIP(),status:randomData.randomStatus(),hostname:randomData.randomHostname()},
        ],
      }));
      console.log("[module] sent fake scan result");
    }, 10000);
  });

  ws.addEventListener("message", (event) => {
    const msg = JSON.parse(event.data);
    console.log("[module] received command:", msg);

    if (msg.type === "run_scan") {
      console.log(`[module] would scan ${msg.cidr} here`);
    }
  });

  ws.addEventListener("close", () => {
    if (scanInterval) clearInterval(scanInterval);
    console.log(`[module] disconnected, retrying in ${RECONNECT_DELAY_MS}ms...`);
    setTimeout(connect, RECONNECT_DELAY_MS);
  });

  ws.addEventListener("error", (err) => {
    console.error("[module] error:", err);
  });
}

connect();

