const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.send("VELORA backend çalışıyor! 🚀");
});

app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        message: "VELORA API aktif"
    });
});

app.post("/api/order", (req, res) => {
    const order = req.body;

    console.log("");
    console.log("================================");
    console.log("YENİ VELORA SİPARİŞİ");
    console.log("================================");
    console.log(order);
    console.log("================================");
    console.log("");

    res.json({
        success: true,
        message: "Sipariş başarıyla alındı!"
    });
});

app.post("/api/test-payment", (req, res) => {
    const payment = req.body;

    console.log("");
    console.log("================================");
    console.log("TEST ÖDEME");
    console.log("================================");
    console.log("Tutar:", payment.total, "TL");
    console.log("Durum: BAŞARILI");
    console.log("================================");
    console.log("");

    res.json({
        success: true,
        paymentStatus: "paid",
        message: "Test ödeme başarılı."
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`VELORA backend ${PORT} portunda çalışıyor.`);
});