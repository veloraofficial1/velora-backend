const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 3000;
const ORDER_EMAIL = "sbkorkmaz60@gmail.com";

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

async function sendOrderEmail(order) {
    const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
            "Authorization": `Bearer ${process.env.RESEND_API_KEY}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            from: "VELORA <onboarding@resend.dev>",
            to: [ORDER_EMAIL],
            subject: "Yeni VELORA Siparişi",
            html: `
                <h2>Yeni VELORA Siparişi</h2>
                <p><strong>Müşteri:</strong> ${order.customer?.name || "-"}</p>
                <p><strong>Telefon:</strong> ${order.customer?.phone || "-"}</p>
                <p><strong>Adres:</strong> ${order.customer?.address || "-"}</p>
                <p><strong>Sipariş Notu:</strong> ${order.customer?.note || "-"}</p>
                <h3>Ürünler</h3>
                <pre>${JSON.stringify(order.items || [], null, 2)}</pre>
                <p><strong>Toplam:</strong> ${order.total || 0} TL</p>
            `
        })
    });

    const data = await response.json();

    if (!response.ok) {
        console.error("Resend hatası:", data);
        throw new Error("E-posta gönderilemedi.");
    }

    console.log("Sipariş e-postası gönderildi:", data);
}

app.post("/api/order", async (req, res) => {
    const order = req.body;

    console.log("YENİ VELORA SİPARİŞİ:");
    console.log(order);

    try {
        await sendOrderEmail(order);

        res.json({
            success: true,
            message: "Sipariş başarıyla alındı ve e-posta gönderildi!"
        });
    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Sipariş alındı fakat e-posta gönderilemedi."
        });
    }
});

app.post("/api/test-payment", (req, res) => {
    const payment = req.body;

    console.log("TEST ÖDEME");
    console.log("Tutar:", payment.total, "TL");
    console.log("Durum: BAŞARILI");

    res.json({
        success: true,
        paymentStatus: "paid",
        message: "Test ödeme başarılı."
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`VELORA backend ${PORT} portunda çalışıyor.`);
});