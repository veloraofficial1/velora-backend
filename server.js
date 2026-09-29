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
   ESKİ DATABASE MIGRATION
========================= */

try {
  db.exec(`
    ALTER TABLE users
    ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0
  `);
} catch (error) {}

try {
  db.exec(`
    ALTER TABLE users
    ADD COLUMN verification_code_hash TEXT
  `);
} catch (error) {}

try {
  db.exec(`
    ALTER TABLE users
    ADD COLUMN verification_expires_at TEXT
  `);
} catch (error) {}

/* =========================
   TOKEN
========================= */

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}

/* =========================
   USER AUTH
========================= */

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

/* =========================
   ADMIN AUTH
========================= */

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
   RESEND EMAIL
========================= */

async function sendVerificationEmail(email, code) {
  if (!RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY eksik.");
  }

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "VELORA <onboarding@resend.dev>",
        to: [email],
        subject: "VELORA E-posta Doğrulama Kodun",
        text:
`VELORA hesabını doğrulamak için kodun:

${code}

Bu kod 10 dakika geçerlidir.

Eğer bu işlemi sen yapmadıysan bu e-postayı dikkate alma.`
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
   REGISTER
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      passwordConfirm
    } = req.body;

    const cleanUsername =
      String(username || "").trim();

    const cleanEmail =
      String(email || "").trim().toLowerCase();

    if (
      !cleanUsername ||
      !cleanEmail ||
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
    `).get(cleanUsername, cleanEmail);

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message:
          "Bu kullanıcı adı veya e-posta zaten kayıtlı."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const verificationCode =
      crypto.randomInt(100000, 1000000).toString();

    const verificationCodeHash =
      await bcrypt.hash(verificationCode, 10);

    const verificationExpiresAt =
      new Date(
        Date.now() + 10 * 60 * 1000
      ).toISOString();

    const createdAt =
      new Date().toISOString();

    const result = db.prepare(`
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
      VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(
      cleanUsername,
      cleanEmail,
      passwordHash,
      createdAt,
      verificationCodeHash,
      verificationExpiresAt
    );

    try {
      await sendVerificationEmail(
        cleanEmail,
        verificationCode
      );
    } catch (emailError) {
      console.error(
        "DOĞRULAMA E-POSTASI HATASI:",
        emailError
      );

      db.prepare(`
        DELETE FROM users
        WHERE id = ?
      `).run(result.lastInsertRowid);

      return res.status(500).json({
        success: false,
        message:
          "Doğrulama e-postası gönderilemedi. Lütfen daha sonra tekrar deneyin."
      });
    }

    return res.status(201).json({
      success: true,
      message:
        "Hesap oluşturuldu. Doğrulama kodu e-posta adresine gönderildi."
    });

  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Kayıt sırasında hata oluştu."
    });
  }
});

/* =========================
   VERIFY EMAIL
========================= */

app.post(
  "/api/auth/verify-email",
  async (req, res) => {
    try {
      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      const code =
        String(req.body.code || "").trim();

      if (!email || !code) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta ve doğrulama kodu gerekli."
        });
      }

      const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `).get(email);

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });
      }

      if (user.email_verified === 1) {
        return res.json({
          success: true,
          message:
            "E-posta adresi zaten doğrulanmış."
        });
      }

      if (
        !user.verification_code_hash ||
        !user.verification_expires_at
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Geçerli bir doğrulama kodu bulunamadı."
        });
      }

      if (
        new Date(user.verification_expires_at)
          .getTime() < Date.now()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Doğrulama kodunun süresi dolmuş. Yeni kod iste."
        });
      }

      const codeCorrect =
        await bcrypt.compare(
          code,
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
      `).run(user.id);

      return res.json({
        success: true,
        message:
          "E-posta adresin başarıyla doğrulandı."
      });

    } catch (error) {
      console.error(
        "VERIFY EMAIL ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "E-posta doğrulama sırasında hata oluştu."
      });
    }
  }
);

/* =========================
   RESEND VERIFICATION
========================= */

app.post(
  "/api/auth/resend-verification",
  async (req, res) => {
    try {
      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "E-posta gerekli."
        });
      }

      const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `).get(email);

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });
      }

      if (user.email_verified === 1) {
        return res.status(400).json({
          success: false,
          message:
            "Bu e-posta adresi zaten doğrulanmış."
        });
      }

      const verificationCode =
        crypto.randomInt(100000, 1000000).toString();

      const verificationCodeHash =
        await bcrypt.hash(verificationCode, 10);

      const verificationExpiresAt =
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
        verificationCodeHash,
        verificationExpiresAt,
        user.id
      );

      try {
        await sendVerificationEmail(
          email,
          verificationCode
        );
      } catch (emailError) {
        console.error(
          "TEKRAR DOĞRULAMA E-POSTASI HATASI:",
          emailError
        );

        return res.status(500).json({
          success: false,
          message:
            "Doğrulama e-postası gönderilemedi."
        });
      }

      return res.json({
        success: true,
        message:
          "Yeni doğrulama kodu e-posta adresine gönderildi."
      });

    } catch (error) {
      console.error(
        "RESEND VERIFICATION ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Yeni doğrulama kodu gönderilemedi."
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const {
      login,
      username,
      password
    } = req.body;

    const loginValue =
      String(login || username || "").trim();

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
      loginValue.toLowerCase()
    );

    if (!user) {
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
          "Önce e-posta adresini doğrulamalısın."
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

    const safeUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: "user"
    };

    const token =
      createToken(safeUser);

    return res.json({
      success: true,
      message: "Giriş başarılı.",
      user: safeUser,
      token
    });

  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Giriş sırasında hata oluştu."
    });
  }
});

/* =========================
   FORGOT PASSWORD
========================= */

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {
    try {
      const email =
        String(req.body.email || "")
          .trim()
          .toLowerCase();

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "E-posta gerekli."
        });
      }

      const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `).get(email);

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });
      }

      const code =
        crypto.randomInt(100000, 1000000).toString();

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

      await sendVerificationEmail(
        email,
        code
      );

      return res.json({
        success: true,
        message:
          "Şifre sıfırlama kodu e-posta adresine gönderildi."
      });

    } catch (error) {
      console.error(
        "FORGOT PASSWORD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlama kodu gönderilemedi."
      });
    }
  }
);

/* =========================
   RESET PASSWORD
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

      const cleanEmail =
        String(email || "")
          .trim()
          .toLowerCase();

      if (
        !cleanEmail ||
        !code ||
        !password ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta, kod ve şifre bilgileri gerekli."
        });
      }

      if (password !== passwordConfirm) {
        return res.status(400).json({
          success: false,
          message:
            "Şifreler aynı değil."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalı."
        });
      }

      const user = db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `).get(cleanEmail);

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
            "Geçerli bir kod bulunamadı."
        });
      }

      if (
        new Date(user.verification_expires_at)
          .getTime() < Date.now()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Kodun süresi dolmuş."
        });
      }

      const codeCorrect =
        await bcrypt.compare(
          String(code).trim(),
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
        await bcrypt.hash(password, 12);

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

      return res.json({
        success: true,
        message:
          "Şifren başarıyla değiştirildi."
      });

    } catch (error) {
      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlanırken hata oluştu."
      });
    }
  }
);

/* =========================
   CHANGE PASSWORD
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
            "Şifre bilgileri eksik."
        });
      }

      if (newPassword !== newPasswordConfirm) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifreler aynı değil."
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre en az 6 karakter olmalı."
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
          message:
            "Kullanıcı bulunamadı."
        });
      }

      const correct =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!correct) {
        return res.status(401).json({
          success: false,
          message:
            "Mevcut şifre yanlış."
        });
      }

      const newHash =
        await bcrypt.hash(newPassword, 12);

      db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
      `).run(
        newHash,
        req.user.id
      );

      return res.json({
        success: true,
        message:
          "Şifre başarıyla değiştirildi."
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
        message:
          "Kullanıcı bulunamadı."
      });
    }

    return res.json({
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
    const users = db.prepare(`
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
    const id =
      Number(req.params.id);

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

    const result =
      db.prepare(`
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
   ORDER
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
   ORDER EMAIL
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

  const response =
    await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",
        headers: {
          Authorization:
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
