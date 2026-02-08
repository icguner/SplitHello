// SplitHello Relay - Cloudflare Worker
// WebSocket-to-TCP relay using Cloudflare's connect() API.
// DPI sees: normal HTTPS traffic to workers.dev
// Worker relays raw bytes between client WebSocket and target TCP socket.

import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === "/" || url.pathname === "/health") {
      return new Response("SplitHello Relay OK", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    // Only handle /tunnel path
    if (url.pathname !== "/tunnel") {
      return new Response("Not Found", { status: 404 });
    }

    // Must be a WebSocket upgrade request
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    let targetSocket = null;
    let targetWriter = null;

    server.addEventListener("message", async (event) => {
      try {
        if (!targetSocket) {
          // First message: JSON connect command
          // Expected: {"cmd":"connect","host":"discord.com","port":443}
          const cmd = JSON.parse(event.data);

          if (cmd.cmd !== "connect" || !cmd.host || !cmd.port) {
            server.send(JSON.stringify({ status: "error", msg: "Invalid connect command" }));
            server.close(1008, "Invalid command");
            return;
          }

          // Connect to the target using Cloudflare's TCP socket API
          targetSocket = connect({
            hostname: cmd.host,
            port: cmd.port,
          });

          // Pipe target -> client (read from TCP, send via WebSocket)
          const readable = targetSocket.readable;
          const reader = readable.getReader();

          (async () => {
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                if (server.readyState === 1) { // WebSocket.OPEN
                  server.send(value);
                } else {
                  break;
                }
              }
            } catch (e) {
              // Target closed or errored
            } finally {
              try { server.close(1000, "Target closed"); } catch {}
            }
          })();

          targetWriter = targetSocket.writable.getWriter();

          server.send(JSON.stringify({ status: "connected" }));
        } else {
          // Subsequent messages: raw TCP data relay (client -> target)
          let data;
          if (typeof event.data === "string") {
            // Text frame - encode to bytes
            data = new TextEncoder().encode(event.data);
          } else {
            data = event.data;
          }
          await targetWriter.write(data);
        }
      } catch (e) {
        try {
          server.send(JSON.stringify({ status: "error", msg: e.message }));
          server.close(1011, "Internal error");
        } catch {}
      }
    });

    server.addEventListener("close", () => {
      if (targetWriter) {
        try { targetWriter.close(); } catch {}
      }
    });

    server.addEventListener("error", () => {
      if (targetWriter) {
        try { targetWriter.close(); } catch {}
      }
    });

    return new Response(null, { status: 101, webSocket: client });
  },
};
