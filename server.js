import express from "express";
import { createPublicKey, verify } from "crypto";

const app = express();

// IMPORTANT: capture raw body BEFORE json parsing
app.use(express.raw({ type: "*/*" }));

const PRC_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA=";
const publicKey = createPublicKey({ key: Buffer.from(PRC_PUBLIC_KEY_B64, "base64"), format: "der", type: "spki" });

app.post("/webhook", (req, res) => {
  const timestamp = req.headers["x-signature-timestamp"];
  const sigHex    = req.headers["x-signature-ed25519"];

  if (!timestamp || !sigHex) return res.status(401).send("Missing headers");

  const sigBytes = Buffer.from(sigHex, "hex");
  const message  = Buffer.concat([Buffer.from(timestamp, "utf8"), req.body]);

  const isValid = verify(null, message, publicKey, sigBytes);
  if (!isValid) return res.status(401).send("Invalid signature");

  const body = JSON.parse(req.body);
  console.log("Event received:", body);

  // handle your event here
  res.status(200).send("OK");
});

app.listen(process.env.PORT || 3000);
