require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";

if (!JWT_SECRET) {
  console.error("JWT_SECRET eksik!");
  process.exit(1);
}

if (!ADMIN_USERNAME) {
  console.error("ADMIN_USERNAME eksik!");
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD eksik!");
  process.exit(1);
}


/* =========================
   MIDDLEWARE
========================= */

app.use(
  cors({
    origin: [
      "https://veloraofficial1.github.io",
      "http://localhost:3000",
      "http://localhost:5500"
    ],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json());


/* =========================
   DATABASE
========================= */

const db = new Database("velora.db");

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    customer_name TEXT,
    customer_phone TEXT,
    customer_address TEXT,
    customer_note TEXT,
    items_json TEXT NOT NULL,
    total REAL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Yeni',
    created_at TEXT NOT NULL
  );
`);


/* =========================
   YARDIMCI FONKSİYONLAR
========================= */

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}


function authenticateUser(req, res, next) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Yetkilendirme gerekli."
    });
  }

  const token = auth.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Geçersiz veya süresi dolmuş token."
    });
  }
}


function authenticateAdmin(req, res, next) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Admin girişi gerekli."
    });
  }

  const token = auth.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin yetkisi gerekli."
      });
    }

    req.admin = decoded;

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Geçersiz admin token."
    });
  }
}


/* =========================
   ANA SAYFA
========================= */

app.get("/", (req, res) => {
  res.send("VELORA backend çalışıyor! 🚀");
});


/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "VELORA API aktif"
  });
});


/* =========================
   NORMAL KULLANICI KAYIT
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      passwordConfirm
    } = req.body;

    if (
      !username ||
      !email ||
      !password ||
      !passwordConfirm
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Kullanıcı adı, e-posta, şifre ve şifre tekrarı gerekli."
      });
    }

    if (password !== passwordConfirm) {
      return res.status(400).json({
        success: false,
        message: "Şifreler aynı değil."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Şifre en az 6 karakter olmalı."
      });
    }

    const existingUser = db.prepare(`
      SELECT id
      FROM users
      WHERE username = ?
         OR email = ?
    `).get(username, email);

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message:
          "Bu kullanıcı adı veya e-posta zaten kayıtlı."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const createdAt = new Date().toISOString();

    const result = db.prepare(`
      INSERT INTO users
      (
        username,
        email,
        password_hash,
        created_at
      )
      VALUES (?, ?, ?, ?)
    `).run(
      username,
      email,
      passwordHash,
      createdAt
    );

    const user = {
      id: result.lastInsertRowid,
      username,
      email,
      role: "user"
    };

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Hesap oluşturuldu.",
      user,
      token
    });

  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Kayıt sırasında hata oluştu."
    });
  }
});


/* =========================
   NORMAL KULLANICI LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      login,
      username,
      password
    } = req.body;

    const loginValue = login || username;

    if (!loginValue || !password) {
      return res.status(400).json({
        success: false,
        message:
          "Kullanıcı adı/e-posta ve şifre gerekli."
      });
    }

    const user = db.prepare(`
      SELECT *
      FROM users
      WHERE username = ?
         OR email = ?
    `).get(
      loginValue,
      loginValue
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message:
          "Kullanıcı adı veya şifre yanlış."
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message:
          "Kullanıcı adı veya şifre yanlış."
      });
    }

    const safeUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: "user"
    };

    const token = createToken(safeUser);

    res.json({
      success: true,
      message: "Giriş başarılı.",
      user: safeUser,
      token
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Giriş sırasında hata oluştu."
    });
  }
});


/* =========================
   ŞİFRE DEĞİŞTİR
========================= */

app.post(
  "/api/auth/change-password",
  authenticateUser,
  async (req, res) => {

    try {
      if (req.user.role === "admin") {
        return res.status(403).json({
          success: false,
          message:
            "Admin şifresi bu bölümden değiştirilemez."
        });
      }

      const {
        currentPassword,
        newPassword,
        newPasswordConfirm
      } = req.body;

      if (
        !currentPassword ||
        !newPassword ||
        !newPasswordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Mevcut şifre, yeni şifre ve yeni şifre tekrarı gerekli."
        });
      }

      if (newPassword !== newPasswordConfirm) {
        return res.status(400).json({
          success: false,
          message: "Yeni şifreler aynı değil."
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre en az 6 karakter olmalı."
        });
      }

      if (currentPassword === newPassword) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre mevcut şifreyle aynı olamaz."
        });
      }

      const user = db.prepare(`
        SELECT *
        FROM users
        WHERE id = ?
      `).get(req.user.id);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Kullanıcı bulunamadı."
        });
      }

      const currentPasswordCorrect =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!currentPasswordCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "Mevcut şifre yanlış."
        });
      }

      const newPasswordHash =
        await bcrypt.hash(newPassword, 12);

      db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(
        newPasswordHash,
        req.user.id
      );

      return res.json({
        success: true,
        message:
          "Şifren başarıyla değiştirildi. Güvenliğin için tekrar giriş yapmalısın."
      });

    } catch (error) {
      console.error(
        "CHANGE PASSWORD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre değiştirilirken hata oluştu."
      });
    }
  }
);


/* =========================
   ME
========================= */

app.get(
  "/api/auth/me",
  authenticateUser,
  (req, res) => {

    if (req.user.role === "admin") {
      return res.json({
        success: true,
        user: req.user
      });
    }

    const user = db.prepare(`
      SELECT
        id,
        username,
        email,
        created_at
      FROM users
      WHERE id = ?
    `).get(req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Kullanıcı bulunamadı."
      });
    }

    res.json({
      success: true,
      user: {
        ...user,
        role: "user"
      }
    });
  }
);


/* =========================
   ADMIN LOGIN
========================= */

app.post(
  "/api/admin/login",
  (req, res) => {

    console.log("ADMIN LOGIN İSTEĞİ GELDİ");

    try {
      const {
        username,
        password
      } = req.body;

      if (!username || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Admin kullanıcı adı ve şifre gerekli."
        });
      }

      if (
        username !== ADMIN_USERNAME ||
        password !== ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Admin kullanıcı adı veya şifre yanlış."
        });
      }

      const admin = {
        username: ADMIN_USERNAME,
        role: "admin"
      };

      const token = createToken(admin);

      return res.json({
        success: true,
        message: "Admin girişi başarılı.",
        user: admin,
        token
      });

    } catch (error) {
      console.error(
        "ADMIN LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Admin girişinde hata oluştu."
      });
    }
  }
);


/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  authenticateAdmin,
  (req, res) => {

    const userCount = db.prepare(`
      SELECT COUNT(*) AS count
      FROM users
    `).get().count;

    const orderCount = db.prepare(`
      SELECT COUNT(*) AS count
      FROM orders
    `).get().count;

    const newOrderCount = db.prepare(`
      SELECT COUNT(*) AS count
      FROM orders
      WHERE status = 'Yeni'
    `).get().count;

    const totalAmount = db.prepare(`
      SELECT COALESCE(SUM(total), 0) AS total
      FROM orders
      WHERE status != 'İptal'
    `).get().total;

    res.json({
      success: true,
      stats: {
        userCount,
        orderCount,
        newOrderCount,
        totalAmount
      }
    });
  }
);


/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  authenticateAdmin,
  (req, res) => {

    const users = db.prepare(`
      SELECT
        id,
        username,
        email,
        created_at
      FROM users
      ORDER BY id DESC
    `).all();

    res.json({
      success: true,
      users
    });
  }
);


/* =========================
   ADMIN USER DELETE
========================= */

app.delete(
  "/api/admin/users/:id",
  authenticateAdmin,
  (req, res) => {

    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        success: false,
        message:
          "Geçersiz kullanıcı ID."
      });
    }

    const result = db.prepare(`
      DELETE FROM users
      WHERE id = ?
    `).run(id);

    if (result.changes === 0) {
      return res.status(404).json({
        success: false,
        message:
          "Kullanıcı bulunamadı."
      });
    }

    res.json({
      success: true,
      message:
        "Kullanıcı silindi."
    });
  }
);


/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  authenticateAdmin,
  (req, res) => {

    const orders = db.prepare(`
      SELECT *
      FROM orders
      ORDER BY id DESC
    `).all();

    res.json({
      success: true,
      orders
    });
  }
);


/* =========================
   ADMIN ORDER STATUS
========================= */

app.patch(
  "/api/admin/orders/:id/status",
  authenticateAdmin,
  (req, res) => {

    const id = Number(req.params.id);
    const { status } = req.body;

    const allowedStatuses = [
      "Yeni",
      "Hazırlanıyor",
      "Kargoda",
      "Teslim Edildi",
      "İptal"
    ];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message:
          "Geçersiz sipariş durumu."
      });
    }

    const result = db.prepare(`
      UPDATE orders
      SET status = ?
      WHERE id = ?
    `).run(status, id);

    if (result.changes === 0) {
      return res.status(404).json({
        success: false,
        message:
          "Sipariş bulunamadı."
      });
    }

    res.json({
      success: true,
      message:
        "Sipariş durumu güncellendi."
    });
  }
);


/* =========================
   ADMIN ORDER DELETE
========================= */

app.delete(
  "/api/admin/orders/:id",
  authenticateAdmin,
  (req, res) => {

    const id = Number(req.params.id);

    const result = db.prepare(`
      DELETE FROM orders
      WHERE id = ?
    `).run(id);

    if (result.changes === 0) {
      return res.status(404).json({
        success: false,
        message:
          "Sipariş bulunamadı."
      });
    }

    res.json({
      success: true,
      message:
        "Sipariş silindi."
    });
  }
);


/* =========================
   SİPARİŞ OLUŞTUR
========================= */

app.post(
  "/api/order",
  authenticateUser,
  async (req, res) => {

    try {
      const {
        customerName,
        customerPhone,
        customerAddress,
        customerNote,
        items,
        total
      } = req.body;

      if (
        !customerName ||
        !customerPhone ||
        !customerAddress ||
        !items
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Sipariş bilgileri eksik."
        });
      }

      const itemsJson =
        JSON.stringify(items);

      const createdAt =
        new Date().toISOString();

      const result = db.prepare(`
        INSERT INTO orders
        (
          user_id,
          customer_name,
          customer_phone,
          customer_address,
          customer_note,
          items_json,
          total,
          status,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id,
        customerName,
        customerPhone,
        customerAddress,
        customerNote || "",
        itemsJson,
        Number(total) || 0,
        "Yeni",
        createdAt
      );

      res.status(201).json({
        success: true,
        message:
          "Sipariş başarıyla oluşturuldu.",
        orderId:
          result.lastInsertRowid
      });

      if (RESEND_API_KEY) {
        sendOrderEmail({
          orderId:
            result.lastInsertRowid,
          customerName,
          customerPhone,
          customerAddress,
          customerNote,
          items,
          total
        }).catch(error => {
          console.error(
            "E-posta gönderilemedi:",
            error
          );
        });
      }

    } catch (error) {
      console.error(
        "ORDER ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Sipariş oluşturulurken hata oluştu."
      });
    }
  }
);


/* =========================
   RESEND E-POSTA
========================= */

async function sendOrderEmail(order) {

  if (!RESEND_API_KEY) {
    return;
  }

  const itemsText =
    Array.isArray(order.items)
      ? order.items
          .map(
            item =>
              `${item.name || "Ürün"} x${item.quantity || 1}`
          )
          .join("\n")
      : "Ürün bilgisi yok";

  const emailText = `
Yeni VELORA siparişi

Sipariş No: ${order.orderId}

Müşteri:
${order.customerName}

Telefon:
${order.customerPhone}

Adres:
${order.customerAddress}

Not:
${order.customerNote || "-"}

Ürünler:
${itemsText}

Toplam:
${order.total || 0} TL
`;

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        "Authorization":
          `Bearer ${RESEND_API_KEY}`,
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify({
        from:
          "VELORA <onboarding@resend.dev>",
        to:
          ["delivered@resend.dev"],
        subject:
          `VELORA Yeni Sipariş #${order.orderId}`,
        text:
          emailText
      })
    }
  );

  if (!response.ok) {
    const text =
      await response.text();

    throw new Error(
      `Resend hata: ${response.status} ${text}`
    );
  }

  return true;
}


/* =========================
   404
========================= */

app.use(
  (req, res) => {
    res.status(404).json({
      success: false,
      message:
        `Endpoint bulunamadı: ${req.method} ${req.originalUrl}`
    });
  }
);


/* =========================
   GENEL HATA
========================= */

app.use(
  (error, req, res, next) => {

    console.error(
      "SERVER ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Sunucu hatası."
    });
  }
);


/* =========================
   SERVER
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `VELORA API ${PORT} portunda çalışıyor.`
    );

    console.log(
      "Admin login: POST /api/admin/login"
    );

  }
);
