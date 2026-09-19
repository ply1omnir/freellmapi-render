// Test double for FreeLLMAPI: answers on APP_PORT and echoes what it received.
import http from "node:http";
const port = Number(process.env.FAKE_APP_PORT || 18082);
http.createServer(function (req, res) {
  let body = "";
  req.on("data", function (c) { body += c; });
  req.on("end", function () {
    res.writeHead(200, { "Content-Type": "application/json", "x-served-by": "fake-app" });
    res.end(JSON.stringify({
      server: "fake-app",
      method: req.method,
      path: req.url,
      xff: req.headers["x-forwarded-for"] || null,
      xfh: req.headers["x-forwarded-host"] || null,
      xfp: req.headers["x-forwarded-proto"] || null,
      host: req.headers.host || null,
      bodyBytes: body.length,
    }));
  });
}).listen(port, "127.0.0.1", function () { console.log("fake-app on " + port); });
