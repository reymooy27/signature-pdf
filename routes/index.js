const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const { PDFDocument } = require("pdf-lib");
const fs = require("fs").promises;
const path = require("path");
const qr = require("qrcode");

router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

router.get("/generate-key", function (req, res) {
  let { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "der",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "der",
    },
  });

  res.send({
    publicKey: publicKey.toString("base64"),
    privateKey: privateKey.toString("base64"),
  });
});

router.post("/sign", async (req, res) => {
  let data = req.body.data;
  let privateKey = req.body.privateKey;

  privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKey, "base64"),
    type: "pkcs8",
    format: "der",
  });

  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();

  const signature = sign.sign(privateKey).toString("base64");

  try {
    const publicFolderPath = path.join(__dirname, "..", "public");
    const imagePath = path.join(publicFolderPath, "testing.png");
    const pdfPath = path.join(publicFolderPath, "testing.pdf");
    const imageBytes = await fs.readFile(imagePath);
    const pdfBytes = await fs.readFile(pdfPath);
    const pdfDoc = await PDFDocument.load(pdfBytes);

    qr.toFile(
      imagePath,
      `${signature}`,
      {
        errorCorrectionLevel: "H",
      },
      function (err) {
        if (err) throw err;
        console.log("QR code saved!");
      },
    );

    const pngImage = await pdfDoc.embedPng(imageBytes);

    const pngDims = pngImage.scale(0.3);

    const page = pdfDoc.getPage(0);

    page.drawImage(pngImage, {
      x: page.getWidth() / 2 - pngDims.width / 2,
      y: page.getHeight() - 150,
      width: pngDims.width,
      height: pngDims.height,
    });

    const signedPdfPath = path.join(publicFolderPath, "document_signed.pdf"); // Adjust the destination path
    await fs.writeFile(signedPdfPath, await pdfDoc.save());
    //
    res.send({ success: true, signedPdfPath });
  } catch (error) {
    console.error(error);
    res.status(500).send({ success: false, error: error.message });
  }
});

router.post("/verify", async (req, res) => {
  let { data, publicKey, signature } = req.body;

  publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKey, "base64"),
    type: "spki",
    format: "der",
  });
  try {
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    verify.end();

    let result = verify.verify(publicKey, Buffer.from(signature, "base64"));

    res.send({ verify: result });
  } catch (err) {
    res.send({ err: err });
  }
});

module.exports = router;
