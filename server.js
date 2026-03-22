import express from "express";
import { createVerify } from "crypto";

const app = express();

app.use((req, res, next) => {
  let data = [];
  req.on("data", chunk => data.push(chunk));
  req.on("end", () => {
    req.rawBody = Buffer.concat(data);
    next();
  });
});

const PRC_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=";

app.post("/webhook", (req, res) => {
  const timestamp = req.headers["x-signature-timestamp"];
  const sigHex    = req.headers["x-signature-ed25519"];

  if (!timestamp || !sigHex) return res.status(401).send("Missing headers");

  try {
    const { createPublicKey, verify } = await import("crypto");
    const pubKeyDer = Buffer.from(PRC_PUBLIC_KEY_B64, "base64");
    const publicKey = createPublicKey({ key: pubKeyDer, format: "der", type: "spki" });
    const sigBytes  = Buffer.from(sigHex, "hex");
    const message   = Buffer.concat([Buffer.from(timestamp, "utf8"), req.rawBody]);

    const isValid = verify(null, message, publicKey, sigBytes);
    if (!isValid) return res.status(401).send("Invalid signature");

    console.log("Event:", JSON.parse(req.rawBody));
    res.status(200).send("OK");
  } catch (e) {
    console.error(e);
    res.status(401).send("Verification error");
  }
});

app.listen(process.env.PORT || 3000, () => console.log("Running"));
