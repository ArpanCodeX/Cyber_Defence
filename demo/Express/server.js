const express = require("express");

const app = express();
const port = Number(process.env.PORT || 8081);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "healthy", service: "express-demo" });
});

app.use((req, res) => {
  res.json({
    service: "authorized Express demo backend",
    method: req.method,
    path: req.path,
    query: req.query,
    body: req.body,
    receivedHeaders: {
      host: req.headers.host,
      "user-agent": req.headers["user-agent"],
      "x-real-ip": req.headers["x-real-ip"],
      "x-forwarded-for": req.headers["x-forwarded-for"],
    },
  });
});

app.listen(port, "0.0.0.0", () => {
  console.log(`Express demo listening on port ${port}`);
});