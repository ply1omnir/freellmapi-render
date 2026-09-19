#!/usr/bin/env node
// Test double for mitmdump+transparent.py: answers on MASK_PORT and pretends to mask.
import http from "node:http";
const port = Number(process.env.MASK_PORT || 19081);
http.createServer(function (req, res) {
  // Test hook: lets the smoke test simulate an engine crash without needing
  // process tooling inside the test container.
  if (String(req.url || "").indexOf("/__die") === 0) {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("dying");
    setTimeout(function () { process.exit(1); }, 50);
    return;
  }
  let body = "";
  req.on("data", function (c) { body += c; });
  req.on("end", function () {
    res.writeHead(200, { "Content-Type": "application/json", "x-served-by": "fake-maskit" });
    res.end(JSON.stringify({
      server: "fake-maskit",
      method: req.method,
      path: req.url,
      host: req.headers.host || null,
      xff: req.headers["x-forwarded-for"] || null,
      xfh: req.headers["x-forwarded-host"] || null,
      maskedBody: body.replace(/sk-[A-Za-z0-9]+/g, "{{APIKEY_test}}"),
    }));
  });
}).listen(port, "127.0.0.1", function () { console.log("fake-maskit on " + port); });
