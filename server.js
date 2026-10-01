require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
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
    created_at TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    verification_code_hash TEXT,
    verification_expires_at TEXT
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
   ESKİ VERİTABANINA KOLON EKLE
========================= */

try {
  db.prepare(`
    ALTER TABLE users
    ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0
  `).run();
} catch (error) {
  // Kolon zaten varsa sorun yok.
}

try {
  db.prepare(`
    ALTER TABLE users
    ADD COLUMN verification_code_hash TEXT
  `).run();
} catch (error) {
  // Kolon zaten varsa sorun yok.
}

try {
  db.prepare(`
    ALTER TABLE users
    ADD COLUMN verification_expires_at TEXT
  `).run();
} catch (error) {
  // Kolon zaten varsa sorun yok.
}

/* =========================
   YARDIMCI FONKSİYONLAR
========================= */

function createToken(payload) {
  return jwt.sign(
    payload,
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
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
   RESEND E-POSTA
========================= */

async function sendVerificationEmail(email, code) {
  if (!RESEND_API_KEY) {
    throw new Error(
      "RESEND_API_KEY Render ortam değişkenlerinde bulunamadı."
    );
  }

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",

      headers: {
        "Authorization": `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        from: "VELORA <onboarding@resend.dev>",
        to: [email],
        subject: "VELORA E-posta Doğrulama Kodun",

        text: `VELORA hesabını doğrulamak için kodun:

${code}

Bu kod 10 dakika geçerlidir.

Bu işlemi sen yapmadıysan bu e-postayı dikkate alma.`
      })
    }
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Resend hata: ${response.status} ${text}`
    );
  }

  return true;
}

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

  const response =
    await fetch(
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
          from: "VELORA <onboarding@resend.dev>",
          to: ["delivered@resend.dev"],
          subject:
            `VELORA Yeni Sipariş #${order.orderId}`,
          text: emailText
        })
      }
    );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Resend hata: ${response.status} ${text}`
    );
  }

  return true;
}

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
   KULLANICI KAYIT
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password
    } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Kullanıcı adı, e-posta ve şifre gerekli."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Şifre en az 6 karakter olmalı."
      });
    }

    const normalizedEmail =
      email.trim().toLowerCase();

    const normalizedUsername =
      username.trim();

    const existingUser =
      db.prepare(`
        SELECT id
        FROM users
        WHERE username = ?
           OR email = ?
      `).get(
        normalizedUsername,
        normalizedEmail
      );

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message:
          "Bu kullanıcı adı veya e-posta zaten kayıtlı."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const code =
      crypto
        .randomInt(100000, 1000000)
        .toString();

    const codeHash =
      await bcrypt.hash(code, 10);

    const expiresAt =
      new Date(
        Date.now() + 10 * 60 * 1000
      ).toISOString();

    const createdAt =
      new Date().toISOString();

    const result =
      db.prepare(`
        INSERT INTO users
        (
          username,
          email,
          password_hash,
          created_at,
          email_verified,
          verification_code_hash,
          verification_expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        normalizedUsername,
        normalizedEmail,
        passwordHash,
        createdAt,
        0,
        codeHash,
        expiresAt
      );

    try {
      await sendVerificationEmail(
        normalizedEmail,
        code
      );
    } catch (emailError) {
      console.error(
        "DOĞRULAMA E-POSTASI HATASI:",
        emailError
      );

      db.prepare(`
        DELETE FROM users
        WHERE id = ?
      `).run(
        result.lastInsertRowid
      );

      return res.status(500).json({
        success: false,
        message:
          "Doğrulama e-postası gönderilemedi."
      });
    }

    res.status(201).json({
      success: true,
      message:
        "Hesap oluşturuldu. Doğrulama kodu e-posta adresine gönderildi."
    });

  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      success: false,
      message:
        "Kayıt sırasında hata oluştu."
    });
  }
});

/* =========================
   E-POSTA DOĞRULAMA
========================= */

app.post(
  "/api/auth/verify-email",
  async (req, res) => {

    try {
      const {
        email,
        code
      } = req.body;

      if (!email || !code) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta ve doğrulama kodu gerekli."
        });
      }

      const normalizedEmail =
        email.trim().toLowerCase();

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          normalizedEmail
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta adresiyle kayıtlı kullanıcı bulunamadı."
        });
      }

      if (user.email_verified === 1) {
        return res.json({
          success: true,
          message:
            "E-posta zaten doğrulanmış."
        });
      }

      if (
        !user.verification_expires_at ||
        !user.verification_code_hash
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Geçerli bir doğrulama kodu bulunamadı."
        });
      }

      if (
        new Date(
          user.verification_expires_at
        ) < new Date()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Doğrulama kodunun süresi dolmuş. Yeni kod iste."
        });
      }

      const codeCorrect =
        await bcrypt.compare(
          String(code),
          user.verification_code_hash
        );

      if (!codeCorrect) {
        return res.status(400).json({
          success: false,
          message:
            "Doğrulama kodu yanlış."
        });
      }

      db.prepare(`
        UPDATE users
        SET
          email_verified = 1,
          verification_code_hash = NULL,
          verification_expires_at = NULL
        WHERE id = ?
      `).run(
        user.id
      );

      res.json({
        success: true,
        message:
          "E-posta başarıyla doğrulandı."
      });

    } catch (error) {

      console.error(
        "VERIFY EMAIL ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "E-posta doğrulama sırasında hata oluştu."
      });
    }
  }
);

/* =========================
   DOĞRULAMA KODUNU TEKRAR GÖNDER
========================= */

app.post(
  "/api/auth/resend-verification",
  async (req, res) => {

    try {
      const {
        email
      } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta adresi gerekli."
        });
      }

      const normalizedEmail =
        email.trim().toLowerCase();

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          normalizedEmail
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta adresiyle kayıtlı kullanıcı bulunamadı."
        });
      }

      if (user.email_verified === 1) {
        return res.status(400).json({
          success: false,
          message:
            "Bu e-posta adresi zaten doğrulanmış."
        });
      }

      const code =
        crypto
          .randomInt(100000, 1000000)
          .toString();

      const codeHash =
        await bcrypt.hash(code, 10);

      const expiresAt =
        new Date(
          Date.now() + 10 * 60 * 1000
        ).toISOString();

      db.prepare(`
        UPDATE users
        SET
          verification_code_hash = ?,
          verification_expires_at = ?
        WHERE id = ?
      `).run(
        codeHash,
        expiresAt,
        user.id
      );

      try {
        await sendVerificationEmail(
          normalizedEmail,
          code
        );
      } catch (emailError) {

        console.error(
          "TEKRAR E-POSTA HATASI:",
          emailError
        );

        return res.status(500).json({
          success: false,
          message:
            "Doğrulama e-postası gönderilemedi."
        });
      }

      res.json({
        success: true,
        message:
          "Yeni doğrulama kodu gönderildi."
      });

    } catch (error) {

      console.error(
        "RESEND VERIFICATION ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Yeni doğrulama kodu gönderilirken hata oluştu."
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/auth/login",
  async (req, res) => {

    try {

      const {
        login,
        username,
        password
      } = req.body;

      const loginValue =
        login || username;

      if (!loginValue || !password) {
        return res.status(400).json({
          success: false,
          message:
            "Kullanıcı adı/e-posta ve şifre gerekli."
        });
      }

      const user =
        db.prepare(`
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

      const passwordCorrect =
        await bcrypt.compare(
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

      if (user.email_verified !== 1) {
        return res.status(403).json({
          success: false,
          message:
            "Önce e-posta adresini doğrulaman gerekiyor."
        });
      }

      const safeUser = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: "user"
      };

      const token =
        createToken(safeUser);

      res.json({
        success: true,
        message:
          "Giriş başarılı.",
        user: safeUser,
        token
      });

    } catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Giriş sırasında hata oluştu."
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

    const user =
      db.prepare(`
        SELECT
          id,
          username,
          email,
          created_at,
          email_verified
        FROM users
        WHERE id = ?
      `).get(
        req.user.id
      );

    if (!user) {
      return res.status(404).json({
        success: false,
        message:
          "Kullanıcı bulunamadı."
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
   ŞİFRE UNUTMA
========================= */

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {

    try {

      const {
        email
      } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta adresi gerekli."
        });
      }

      const normalizedEmail =
        email.trim().toLowerCase();

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          normalizedEmail
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta adresiyle kayıtlı kullanıcı bulunamadı."
        });
      }

      const code =
        crypto
          .randomInt(100000, 1000000)
          .toString();

      const codeHash =
        await bcrypt.hash(code, 10);

      const expiresAt =
        new Date(
          Date.now() + 10 * 60 * 1000
        ).toISOString();

      db.prepare(`
        UPDATE users
        SET
          verification_code_hash = ?,
          verification_expires_at = ?
        WHERE id = ?
      `).run(
        codeHash,
        expiresAt,
        user.id
      );

      const response =
        await fetch(
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

              to: [normalizedEmail],

              subject:
                "VELORA Şifre Sıfırlama Kodun",

              text:
                `Şifre sıfırlama kodun: ${code}

Bu kod 10 dakika geçerlidir.`
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

      res.json({
        success: true,
        message:
          "Şifre sıfırlama kodu gönderildi."
      });

    } catch (error) {

      console.error(
        "FORGOT PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlama kodu gönderilemedi."
      });
    }
  }
);

/* =========================
   ŞİFRE SIFIRLA
========================= */

app.post(
  "/api/auth/reset-password",
  async (req, res) => {

    try {

      const {
        email,
        code,
        password,
        passwordConfirm
      } = req.body;

      if (
        !email ||
        !code ||
        !password ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Tüm alanları doldurun."
        });
      }

      if (password !== passwordConfirm) {
        return res.status(400).json({
          success: false,
          message:
            "Şifreler aynı olmalı."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalı."
        });
      }

      const normalizedEmail =
        email.trim().toLowerCase();

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `).get(
          normalizedEmail
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı."
        });
      }

      if (
        !user.verification_code_hash ||
        !user.verification_expires_at
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Geçerli sıfırlama kodu bulunamadı."
        });
      }

      if (
        new Date(
          user.verification_expires_at
        ) < new Date()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Kodun süresi dolmuş."
        });
      }

      const codeCorrect =
        await bcrypt.compare(
          String(code),
          user.verification_code_hash
        );

      if (!codeCorrect) {
        return res.status(400).json({
          success: false,
          message:
            "Kod yanlış."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      db.prepare(`
        UPDATE users
        SET
          password_hash = ?,
          verification_code_hash = NULL,
          verification_expires_at = NULL
        WHERE id = ?
      `).run(
        passwordHash,
        user.id
      );

      res.json({
        success: true,
        message:
          "Şifren başarıyla değiştirildi."
      });

    } catch (error) {

      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlama sırasında hata oluştu."
      });
    }
  }
);

/* =========================
   ŞİFRE DEĞİŞTİR
========================= */

app.post(
  "/api/auth/change-password",
  authenticateUser,
  async (req, res) => {

    try {

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
            "Tüm alanları doldurun."
        });
      }

      if (
        newPassword !== newPasswordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifreler aynı olmalı."
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre en az 6 karakter olmalı."
        });
      }

      const user =
        db.prepare(`
          SELECT *
          FROM users
          WHERE id = ?
        `).get(
          req.user.id
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı."
        });
      }

      const currentCorrect =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!currentCorrect) {
        return res.status(401).json({
          success: false,
          message:
            "Mevcut şifre yanlış."
        });
      }

      const newPasswordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(
        newPasswordHash,
        user.id
      );

      res.json({
        success: true,
        message:
          "Şifren başarıyla değiştirildi."
      });

    } catch (error) {

      console.error(
        "CHANGE PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        success: false,
        message:
          "Şifre değiştirme sırasında hata oluştu."
      });
    }
  }
);

/* =========================
   ADMIN LOGIN
========================= */

app.post(
  "/api/admin/login",
  (req, res) => {

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

      const token =
        createToken(admin);

      return res.json({
        success: true,
        message:
          "Admin girişi başarılı.",
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

    const userCount =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM users
      `).get().count;

    const orderCount =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM orders
      `).get().count;

    const newOrderCount =
      db.prepare(`
        SELECT COUNT(*) AS count
        FROM orders
        WHERE status = 'Yeni'
      `).get().count;

    const totalAmount =
      db.prepare(`
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

    const users =
      db.prepare(`
        SELECT
          id,
          username,
          email,
          created_at,
          email_verified
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

    const id =
      Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({
        success: false,
        message:
          "Geçersiz kullanıcı ID."
      });
    }

    const result =
      db.prepare(`
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

    const orders =
      db.prepare(`
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

    const id =
      Number(req.params.id);

    const {
      status
    } = req.body;

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

    const result =
      db.prepare(`
        UPDATE orders
        SET status = ?
        WHERE id = ?
      `).run(
        status,
        id
      );

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

    const id =
      Number(req.params.id);

    const result =
      db.prepare(`
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

      const result =
        db.prepare(`
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

        }).catch(
          error =>
            console.error(
              "E-posta gönderilemedi:",
              error
            )
        );
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
   404 JSON
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
// ======================================================
// PRODUCT REVIEWS
// ======================================================

// Ürün yorumları tablosu
db.run(`
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.run(`
  CREATE INDEX IF NOT EXISTS idx_reviews_product_id
  ON reviews(product_id)
`);

// Müşteri: ürün yorumlarını getir
app.get("/api/reviews/:productId", (req, res) => {

  const productId =
    Number(req.params.productId);

  if (
    !Number.isInteger(productId) ||
    productId <= 0
  ) {
    return res.status(400).json({
      success: false,
      message: "Geçersiz ürün ID."
    });
  }

  db.all(
    `
      SELECT
        r.id,
        r.product_id,
        r.user_id,
        r.rating,
        r.comment,
        r.created_at,
        u.username
      FROM reviews r
      LEFT JOIN users u
        ON u.id = r.user_id
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `,
    [productId],
    (error, rows) => {

      if (error) {

        console.error(
          "Reviews GET hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Değerlendirmeler alınamadı."
        });
      }

      res.json({
        success: true,
        reviews: rows || []
      });

    }
  );

});


// Müşteri: yeni yorum gönder
app.post(
  "/api/reviews",
  authMiddleware,
  (req, res) => {

    const productId =
      Number(req.body.productId);

    const rating =
      Number(req.body.rating);

    const comment =
      String(
        req.body.comment || ""
      ).trim();


    if (
      !Number.isInteger(productId) ||
      productId <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Geçersiz ürün."
      });

    }


    if (
      !Number.isInteger(rating) ||
      rating < 1 ||
      rating > 5
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Puan 1 ile 5 arasında olmalıdır."
      });

    }


    if (!comment) {

      return res.status(400).json({
        success: false,
        message:
          "Lütfen yorumunuzu yazın."
      });

    }


    if (comment.length > 1000) {

      return res.status(400).json({
        success: false,
        message:
          "Yorum en fazla 1000 karakter olabilir."
      });

    }


    db.get(
      "SELECT id FROM products WHERE id = ?",
      [productId],
      (productError, product) => {

        if (productError) {

          console.error(
            "Ürün kontrol hatası:",
            productError
          );

          return res.status(500).json({
            success: false,
            message:
              "Ürün kontrol edilemedi."
          });

        }


        if (!product) {

          return res.status(404).json({
            success: false,
            message:
              "Ürün bulunamadı."
          });

        }


        db.run(
          `
            INSERT INTO reviews
            (
              product_id,
              user_id,
              rating,
              comment
            )
            VALUES (?, ?, ?, ?)
          `,
          [
            productId,
            req.user.id,
            rating,
            comment
          ],
          function (error) {

            if (error) {

              console.error(
                "Review INSERT hatası:",
                error
              );

              return res.status(500).json({
                success: false,
                message:
                  "Yorum gönderilemedi."
              });

            }


            res.status(201).json({

              success: true,

              message:
                "Değerlendirmeniz başarıyla gönderildi.",

              review: {

                id: this.lastID,

                product_id:
                  productId,

                user_id:
                  req.user.id,

                rating:
                  rating,

                comment:
                  comment

              }

            });

          }
        );

      }
    );

  }
);


// ======================================================
// ADMIN REVIEWS
// ======================================================

// Admin: bütün yorumları getir
app.get(
  "/api/admin/reviews",
  (req, res) => {

    db.all(
      `
        SELECT
          r.id,
          r.product_id,
          r.user_id,
          r.rating,
          r.comment,
          r.created_at,
          u.username,
          u.email
        FROM reviews r
        LEFT JOIN users u
          ON u.id = r.user_id
        ORDER BY r.created_at DESC
      `,
      [],
      (error, rows) => {

        if (error) {

          console.error(
            "Admin reviews GET hatası:",
            error
          );

          return res.status(500).json({
            success: false,
            message:
              "Değerlendirmeler alınamadı."
          });

        }


        res.json({

          success: true,

          reviews:
            rows || []

        });

      }
    );

  }
);


// Admin: yorum sil
app.delete(
  "/api/admin/reviews/:id",
  (req, res) => {

    const reviewId =
      Number(req.params.id);


    if (
      !Number.isInteger(reviewId) ||
      reviewId <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "Geçersiz yorum ID."
      });

    }


    db.run(
      "DELETE FROM reviews WHERE id = ?",
      [reviewId],
      function (error) {

        if (error) {

          console.error(
            "Admin review DELETE hatası:",
            error
          );

          return res.status(500).json({
            success: false,
            message:
              "Yorum silinemedi."
          });

        }


        if (this.changes === 0) {

          return res.status(404).json({
            success: false,
            message:
              "Yorum bulunamadı."
          });

        }


        res.json({

          success: true,

          message:
            "Yorum başarıyla silindi."

        });

      }
    );

  }
);
