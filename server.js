const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(express.json({ limit: "2mb" }));

app.use(
  cors({
    origin: [
      "https://veloraofficial1.github.io",
      "http://localhost:3000",
      "http://localhost:5500",
    ],
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (
  !JWT_SECRET ||
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD ||
  !SUPABASE_URL ||
  !SUPABASE_SERVICE_ROLE_KEY
) {
  console.error("Gerekli environment variable eksik.");
  process.exit(1);
}

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

/* =========================================================
   GENEL YARDIMCI FONKSİYONLAR
========================================================= */

function createToken(payload, expiresIn = "7d") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function generateVerificationCode() {
  return crypto.randomInt(100000, 1000000).toString();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeUsername(username) {
  return String(username || "").trim();
}

function authenticateUser(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Giriş yapmanız gerekiyor.",
      });
    }

    const token = header.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded || decoded.type !== "user") {
      return res.status(401).json({
        success: false,
        message: "Geçersiz kullanıcı oturumu.",
      });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Oturum geçersiz veya süresi dolmuş.",
    });
  }
}

function authenticateAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Yönetici girişi gerekiyor.",
      });
    }

    const token = header.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded || decoded.type !== "admin") {
      return res.status(401).json({
        success: false,
        message: "Geçersiz yönetici oturumu.",
      });
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Yönetici oturumu geçersiz veya süresi dolmuş.",
    });
  }
}

/* =========================================================
   BREVO
========================================================= */

async function sendBrevoEmail({
  to,
  subject,
  htmlContent,
}) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || "VELORA";

  if (!apiKey || !senderEmail) {
    throw new Error("Brevo environment variable eksik.");
  }

  const response = await fetch(
    "https://api.brevo.com/v3/smtp/email",
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "api-key": apiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sender: {
          name: senderName,
          email: senderEmail,
        },
        to: [
          {
            email: to,
          },
        ],
        subject,
        htmlContent,
      }),
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Brevo hatası:", data);

    throw new Error(
      data?.message || "E-posta gönderilemedi."
    );
  }

  return data;
}

/* =========================================================
   ANA SAYFA
========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "VELORA backend çalışıyor.",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
  });
});

/* =========================================================
   KAYIT
   TELEFON NUMARASI YOK
========================================================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      passwordConfirm,
    } = req.body;

    const cleanUsername = normalizeUsername(username);
    const cleanEmail = normalizeEmail(email);

    if (
      !cleanUsername ||
      !cleanEmail ||
      !password ||
      !passwordConfirm
    ) {
      return res.status(400).json({
        success: false,
        message: "Lütfen tüm alanları doldurun.",
      });
    }

    if (password !== passwordConfirm) {
      return res.status(400).json({
        success: false,
        message: "Şifreler eşleşmiyor.",
      });
    }

    if (cleanUsername.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Kullanıcı adı en az 3 karakter olmalıdır.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Şifre en az 6 karakter olmalıdır.",
      });
    }

    const emailRegex =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Geçerli bir e-posta adresi girin.",
      });
    }

    /* Kullanıcı adı kontrolü */
    const { data: existingUsername, error: usernameCheckError } =
      await supabase
        .from("users")
        .select("id")
        .eq("username", cleanUsername)
        .maybeSingle();

    if (usernameCheckError) {
      console.error(
        "Kullanıcı adı kontrol hatası:",
        usernameCheckError
      );

      return res.status(500).json({
        success: false,
        message: "Kullanıcı kontrolü sırasında hata oluştu.",
      });
    }

    if (existingUsername) {
      return res.status(409).json({
        success: false,
        message: "Bu kullanıcı adı zaten kullanılıyor.",
      });
    }

    /* E-posta kontrolü */
    const { data: existingEmail, error: emailCheckError } =
      await supabase
        .from("users")
        .select("id")
        .eq("email", cleanEmail)
        .maybeSingle();

    if (emailCheckError) {
      console.error(
        "E-posta kontrol hatası:",
        emailCheckError
      );

      return res.status(500).json({
        success: false,
        message: "E-posta kontrolü sırasında hata oluştu.",
      });
    }

    if (existingEmail) {
      return res.status(409).json({
        success: false,
        message: "Bu e-posta adresi zaten kayıtlı.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const verificationCode = generateVerificationCode();

    const verificationExpiresAt = new Date(
      Date.now() + 15 * 60 * 1000
    ).toISOString();

    const { data: user, error: insertError } =
      await supabase
        .from("users")
        .insert({
          username: cleanUsername,
          email: cleanEmail,
          password_hash: passwordHash,
          email_verified: false,
          verification_code: verificationCode,
          verification_expires_at: verificationExpiresAt,
          role: "user",
        })
        .select(
          "id, username, email, email_verified, role"
        )
        .single();

    if (insertError) {
      console.error(
        "Kullanıcı oluşturma hatası:",
        insertError
      );

      if (insertError.code === "23505") {
        const message =
          String(insertError.message || "").toLowerCase();

        if (message.includes("username")) {
          return res.status(409).json({
            success: false,
            message: "Bu kullanıcı adı zaten kullanılıyor.",
          });
        }

        if (message.includes("email")) {
          return res.status(409).json({
            success: false,
            message: "Bu e-posta adresi zaten kayıtlı.",
          });
        }

        return res.status(409).json({
          success: false,
          message: "Bu bilgilerle kayıtlı bir kullanıcı bulunuyor.",
        });
      }

      return res.status(500).json({
        success: false,
        message: "Kullanıcı oluşturulamadı.",
      });
    }

    try {
      await sendBrevoEmail({
        to: cleanEmail,
        subject: "VELORA E-posta Doğrulama Kodunuz",
        htmlContent: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
            <h1 style="letter-spacing:4px;">VELORA</h1>
            <p>Merhaba <strong>${cleanUsername}</strong>,</p>
            <p>Hesabınızı doğrulamak için aşağıdaki kodu kullanın:</p>

            <div style="
              font-size:32px;
              font-weight:bold;
              letter-spacing:8px;
              padding:20px;
              background:#f4f0e8;
              text-align:center;
              margin:25px 0;
            ">
              ${verificationCode}
            </div>

            <p>Bu kod 15 dakika geçerlidir.</p>
            <p>Eğer bu işlemi siz yapmadıysanız bu e-postayı dikkate almayabilirsiniz.</p>
          </div>
        `,
      });
    } catch (mailError) {
      console.error(
        "Doğrulama e-postası gönderilemedi:",
        mailError
      );
    }

    return res.status(201).json({
      success: true,
      message:
        "Kayıt başarılı. E-posta adresinize doğrulama kodu gönderildi.",
      user,
    });
  } catch (error) {
    console.error(
      "Register genel hata:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Sunucu hatası.",
    });
  }
});

/* =========================================================
   E-POSTA DOĞRULAMA
========================================================= */

app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const code = String(req.body.code || "").trim();

    if (!email || !code) {
      return res.status(400).json({
        success: false,
        message: "E-posta ve doğrulama kodu gereklidir.",
      });
    }

    const { data: user, error } =
      await supabase
        .from("users")
        .select(
          "id, username, email, email_verified, verification_code, verification_expires_at, role"
        )
        .eq("email", email)
        .maybeSingle();

    if (error) {
      console.error(
        "Doğrulama kullanıcı sorgu hatası:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Doğrulama sırasında hata oluştu.",
      });
    }

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Kullanıcı bulunamadı.",
      });
    }

    if (user.email_verified) {
      return res.json({
        success: true,
        message: "E-posta adresiniz zaten doğrulanmış.",
      });
    }

    if (
      !user.verification_code ||
      user.verification_code !== code
    ) {
      return res.status(400).json({
        success: false,
        message: "Doğrulama kodu hatalı.",
      });
    }

    if (
      !user.verification_expires_at ||
      new Date(user.verification_expires_at).getTime() <
        Date.now()
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Doğrulama kodunun süresi dolmuş. Yeni kod isteyin.",
      });
    }

    const { error: updateError } =
      await supabase
        .from("users")
        .update({
          email_verified: true,
          verification_code: null,
          verification_expires_at: null,
        })
        .eq("id", user.id);

    if (updateError) {
      console.error(
        "E-posta doğrulama update hatası:",
        updateError
      );

      return res.status(500).json({
        success: false,
        message: "E-posta doğrulanamadı.",
      });
    }

    return res.json({
      success: true,
      message: "E-posta adresiniz başarıyla doğrulandı.",
    });
  } catch (error) {
    console.error(
      "Verify email genel hata:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Sunucu hatası.",
    });
  }
});

/* =========================================================
   YENİ DOĞRULAMA KODU
========================================================= */

app.post(
  "/api/auth/resend-verification",
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "E-posta adresi gereklidir.",
        });
      }

      const { data: user, error } =
        await supabase
          .from("users")
          .select(
            "id, username, email, email_verified"
          )
          .eq("email", email)
          .maybeSingle();

      if (error) {
        console.error(
          "Resend kullanıcı sorgu hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "İşlem sırasında hata oluştu.",
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Bu e-posta adresiyle kullanıcı bulunamadı.",
        });
      }

      if (user.email_verified) {
        return res.status(400).json({
          success: false,
          message: "Bu e-posta adresi zaten doğrulanmış.",
        });
      }

      const verificationCode =
        generateVerificationCode();

      const verificationExpiresAt = new Date(
        Date.now() + 15 * 60 * 1000
      ).toISOString();

      const { error: updateError } =
        await supabase
          .from("users")
          .update({
            verification_code: verificationCode,
            verification_expires_at:
              verificationExpiresAt,
          })
          .eq("id", user.id);

      if (updateError) {
        console.error(
          "Yeni doğrulama kodu update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message: "Yeni kod oluşturulamadı.",
        });
      }

      await sendBrevoEmail({
        to: user.email,
        subject: "VELORA Yeni Doğrulama Kodunuz",
        htmlContent: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
            <h1 style="letter-spacing:4px;">VELORA</h1>
            <p>Merhaba <strong>${user.username}</strong>,</p>
            <p>Yeni doğrulama kodunuz:</p>

            <div style="
              font-size:32px;
              font-weight:bold;
              letter-spacing:8px;
              padding:20px;
              background:#f4f0e8;
              text-align:center;
              margin:25px 0;
            ">
              ${verificationCode}
            </div>

            <p>Bu kod 15 dakika geçerlidir.</p>
          </div>
        `,
      });

      return res.json({
        success: true,
        message: "Yeni doğrulama kodu gönderildi.",
      });
    } catch (error) {
      console.error(
        "Resend verification genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Yeni doğrulama kodu gönderilemedi.",
      });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const login = String(
      req.body.login || req.body.email || req.body.username || ""
    ).trim();

    const password = String(
      req.body.password || ""
    );

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Kullanıcı adı/e-posta ve şifre gereklidir.",
      });
    }

    const normalizedLogin = login.toLowerCase();

    let user = null;

    const { data: emailUser, error: emailError } =
      await supabase
        .from("users")
        .select(
          "id, username, email, password_hash, email_verified, role"
        )
        .eq("email", normalizedLogin)
        .maybeSingle();

    if (emailError) {
      console.error(
        "Login e-posta sorgu hatası:",
        emailError
      );
    }

    if (emailUser) {
      user = emailUser;
    } else {
      const { data: usernameUser, error: usernameError } =
        await supabase
          .from("users")
          .select(
            "id, username, email, password_hash, email_verified, role"
          )
          .eq("username", login)
          .maybeSingle();

      if (usernameError) {
        console.error(
          "Login kullanıcı adı sorgu hatası:",
          usernameError
        );
      }

      if (usernameUser) {
        user = usernameUser;
      }
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Kullanıcı adı/e-posta veya şifre hatalı.",
      });
    }

    const passwordValid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordValid) {
      return res.status(401).json({
        success: false,
        message: "Kullanıcı adı/e-posta veya şifre hatalı.",
      });
    }

    if (!user.email_verified) {
      return res.status(403).json({
        success: false,
        message:
          "Önce e-posta adresinizi doğrulamanız gerekiyor.",
        emailVerified: false,
        email: user.email,
      });
    }

    const token = createToken(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        type: "user",
      },
      "7d"
    );

    const safeUser = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role || "user",
    };

    return res.json({
      success: true,
      message: "Giriş başarılı.",
      token,
      user: safeUser,
    });
  } catch (error) {
    console.error(
      "Login genel hata:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Sunucu hatası.",
    });
  }
});

/* =========================================================
   ŞİFREMİ UNUTTUM
========================================================= */

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);

      if (!email) {
        return res.status(400).json({
          success: false,
          message: "E-posta adresi gereklidir.",
        });
      }

      const { data: user, error } =
        await supabase
          .from("users")
          .select("id, username, email")
          .eq("email", email)
          .maybeSingle();

      if (error) {
        console.error(
          "Forgot password sorgu hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "İşlem sırasında hata oluştu.",
        });
      }

      /*
       * Güvenlik amacıyla kullanıcı bulunamasa bile
       * aynı genel cevap verilebilir.
       */
      if (!user) {
        return res.json({
          success: true,
          message:
            "Eğer bu e-posta kayıtlıysa şifre sıfırlama kodu gönderildi.",
        });
      }

      const resetCode = generateVerificationCode();

      const resetExpiresAt = new Date(
        Date.now() + 15 * 60 * 1000
      ).toISOString();

      const { error: updateError } =
        await supabase
          .from("users")
          .update({
            reset_code: resetCode,
            reset_expires_at: resetExpiresAt,
          })
          .eq("id", user.id);

      if (updateError) {
        console.error(
          "Reset code update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message: "Şifre sıfırlama kodu oluşturulamadı.",
        });
      }

      await sendBrevoEmail({
        to: user.email,
        subject: "VELORA Şifre Sıfırlama Kodunuz",
        htmlContent: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
            <h1 style="letter-spacing:4px;">VELORA</h1>

            <p>Merhaba <strong>${user.username}</strong>,</p>

            <p>Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>

            <div style="
              font-size:32px;
              font-weight:bold;
              letter-spacing:8px;
              padding:20px;
              background:#f4f0e8;
              text-align:center;
              margin:25px 0;
            ">
              ${resetCode}
            </div>

            <p>Bu kod 15 dakika geçerlidir.</p>
          </div>
        `,
      });

      return res.json({
        success: true,
        message:
          "Eğer bu e-posta kayıtlıysa şifre sıfırlama kodu gönderildi.",
      });
    } catch (error) {
      console.error(
        "Forgot password genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "İşlem sırasında hata oluştu.",
      });
    }
  }
);

/* =========================================================
   ŞİFRE SIFIRLAMA
========================================================= */

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    try {
      const email = normalizeEmail(req.body.email);
      const code = String(req.body.code || "").trim();
      const password = String(req.body.password || "");
      const passwordConfirm = String(
        req.body.passwordConfirm || ""
      );

      if (
        !email ||
        !code ||
        !password ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message: "Lütfen tüm alanları doldurun.",
        });
      }

      if (password !== passwordConfirm) {
        return res.status(400).json({
          success: false,
          message: "Şifreler eşleşmiyor.",
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Şifre en az 6 karakter olmalıdır.",
        });
      }

      const { data: user, error } =
        await supabase
          .from("users")
          .select(
            "id, email, reset_code, reset_expires_at"
          )
          .eq("email", email)
          .maybeSingle();

      if (error) {
        console.error(
          "Reset password sorgu hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "İşlem sırasında hata oluştu.",
        });
      }

      if (!user) {
        return res.status(400).json({
          success: false,
          message: "Kod geçersiz.",
        });
      }

      if (
        !user.reset_code ||
        user.reset_code !== code
      ) {
        return res.status(400).json({
          success: false,
          message: "Şifre sıfırlama kodu hatalı.",
        });
      }

      if (
        !user.reset_expires_at ||
        new Date(user.reset_expires_at).getTime() <
          Date.now()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Şifre sıfırlama kodunun süresi dolmuş.",
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const { error: updateError } =
        await supabase
          .from("users")
          .update({
            password_hash: passwordHash,
            reset_code: null,
            reset_expires_at: null,
          })
          .eq("id", user.id);

      if (updateError) {
        console.error(
          "Şifre update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message: "Şifre değiştirilemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Şifreniz başarıyla sıfırlandı.",
      });
    } catch (error) {
      console.error(
        "Reset password genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ŞİFRE DEĞİŞTİR
========================================================= */

app.post(
  "/api/auth/change-password",
  authenticateUser,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPassword = String(
        req.body.newPassword || ""
      );

      const newPasswordConfirm = String(
        req.body.newPasswordConfirm || ""
      );

      if (
        !currentPassword ||
        !newPassword ||
        !newPasswordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message: "Lütfen tüm alanları doldurun.",
        });
      }

      if (newPassword !== newPasswordConfirm) {
        return res.status(400).json({
          success: false,
          message: "Yeni şifreler eşleşmiyor.",
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          success: false,
          message: "Yeni şifre en az 6 karakter olmalıdır.",
        });
      }

      const { data: user, error } =
        await supabase
          .from("users")
          .select("id, password_hash")
          .eq("id", req.user.id)
          .maybeSingle();

      if (error || !user) {
        return res.status(404).json({
          success: false,
          message: "Kullanıcı bulunamadı.",
        });
      }

      const passwordValid = await bcrypt.compare(
        currentPassword,
        user.password_hash
      );

      if (!passwordValid) {
        return res.status(400).json({
          success: false,
          message: "Mevcut şifreniz hatalı.",
        });
      }

      const passwordHash = await bcrypt.hash(
        newPassword,
        12
      );

      const { error: updateError } =
        await supabase
          .from("users")
          .update({
            password_hash: passwordHash,
          })
          .eq("id", user.id);

      if (updateError) {
        console.error(
          "Change password update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message: "Şifre değiştirilemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Şifreniz başarıyla değiştirildi.",
      });
    } catch (error) {
      console.error(
        "Change password genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ME
========================================================= */

app.get(
  "/api/auth/me",
  authenticateUser,
  async (req, res) => {
    try {
      const { data: user, error } =
        await supabase
          .from("users")
          .select(
            "id, username, email, created_at, email_verified, role"
          )
          .eq("id", req.user.id)
          .maybeSingle();

      if (error) {
        console.error(
          "Me sorgu hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Kullanıcı bilgileri alınamadı.",
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Kullanıcı bulunamadı.",
        });
      }

      return res.json({
        success: true,
        user,
      });
    } catch (error) {
      console.error(
        "Me genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   FAVORİLER
========================================================= */

app.get(
  "/api/favorites",
  authenticateUser,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase
          .from("favorites")
          .select("*")
          .eq("user_id", req.user.id)
          .order("created_at", {
            ascending: false,
          });

      if (error) {
        console.error(
          "Favoriler sorgu hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Favoriler alınamadı.",
        });
      }

      return res.json({
        success: true,
        favorites: data || [],
      });
    } catch (error) {
      console.error(
        "Favorites GET hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

app.post(
  "/api/favorites",
  authenticateUser,
  async (req, res) => {
    try {
      const productId = String(
        req.body.productId || ""
      ).trim();

      if (!productId) {
        return res.status(400).json({
          success: false,
          message: "Ürün ID gereklidir.",
        });
      }

      const { data, error } =
        await supabase
          .from("favorites")
          .upsert(
            {
              user_id: req.user.id,
              product_id: productId,
            },
            {
              onConflict: "user_id,product_id",
            }
          )
          .select("*")
          .single();

      if (error) {
        console.error(
          "Favori ekleme hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Favori eklenemedi.",
        });
      }

      return res.json({
        success: true,
        favorite: data,
      });
    } catch (error) {
      console.error(
        "Favorites POST hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

app.delete(
  "/api/favorites/:productId",
  authenticateUser,
  async (req, res) => {
    try {
      const productId = String(
        req.params.productId || ""
      ).trim();

      const { error } =
        await supabase
          .from("favorites")
          .delete()
          .eq("user_id", req.user.id)
          .eq("product_id", productId);

      if (error) {
        console.error(
          "Favori silme hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Favori silinemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Favorilerden kaldırıldı.",
      });
    } catch (error) {
      console.error(
        "Favorites DELETE hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   KULLANICININ SİPARİŞLERİ
========================================================= */

app.get(
  "/api/orders/my",
  authenticateUser,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase
          .from("orders")
          .select("*")
          .eq("user_id", req.user.id)
          .order("created_at", {
            ascending: false,
          });

      if (error) {
        console.error(
          "Kullanıcı siparişleri hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Siparişler alınamadı.",
        });
      }

      return res.json({
        success: true,
        orders: data || [],
      });
    } catch (error) {
      console.error(
        "Orders my genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
  "/api/admin/login",
  async (req, res) => {
    try {
      const username = String(
        req.body.username || ""
      ).trim();

      const password = String(
        req.body.password || ""
      );

      if (
        username !== ADMIN_USERNAME ||
        password !== ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          success: false,
          message: "Yönetici kullanıcı adı veya şifre hatalı.",
        });
      }

      const token = createToken(
        {
          username: ADMIN_USERNAME,
          type: "admin",
        },
        "12h"
      );

      return res.json({
        success: true,
        message: "Yönetici girişi başarılı.",
        token,
      });
    } catch (error) {
      console.error(
        "Admin login hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN STATS
========================================================= */

app.get(
  "/api/admin/stats",
  authenticateAdmin,
  async (req, res) => {
    try {
      const [
        usersResult,
        ordersResult,
      ] = await Promise.all([
        supabase
          .from("users")
          .select("id", {
            count: "exact",
            head: true,
          }),

        supabase
          .from("orders")
          .select("id", {
            count: "exact",
            head: true,
          }),
      ]);

      if (usersResult.error) {
        console.error(
          "Admin users count hatası:",
          usersResult.error
        );
      }

      if (ordersResult.error) {
        console.error(
          "Admin orders count hatası:",
          ordersResult.error
        );
      }

      return res.json({
        success: true,
        stats: {
          users: usersResult.count || 0,
          orders: ordersResult.count || 0,
        },
      });
    } catch (error) {
      console.error(
        "Admin stats hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "İstatistikler alınamadı.",
      });
    }
  }
);

/* =========================================================
   ADMIN USERS
   TELEFON YOK
========================================================= */

app.get(
  "/api/admin/users",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase
          .from("users")
          .select(
            "id, username, email, created_at, email_verified, role"
          )
          .order("created_at", {
            ascending: false,
          });

      if (error) {
        console.error(
          "Admin users hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Kullanıcılar alınamadı.",
        });
      }

      return res.json({
        success: true,
        users: data || [],
      });
    } catch (error) {
      console.error(
        "Admin users genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN USER DELETE
========================================================= */

app.delete(
  "/api/admin/users/:id",
  authenticateAdmin,
  async (req, res) => {
    try {
      const userId = req.params.id;

      const { error } =
        await supabase
          .from("users")
          .delete()
          .eq("id", userId);

      if (error) {
        console.error(
          "Admin user delete hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Kullanıcı silinemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Kullanıcı silindi.",
      });
    } catch (error) {
      console.error(
        "Admin user delete genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  authenticateAdmin,
  async (req, res) => {
    try {
      const { data, error } =
        await supabase
          .from("orders")
          .select("*")
          .order("created_at", {
            ascending: false,
          });

      if (error) {
        console.error(
          "Admin orders hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Siparişler alınamadı.",
        });
      }

      return res.json({
        success: true,
        orders: data || [],
      });
    } catch (error) {
      console.error(
        "Admin orders genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN ORDER STATUS
========================================================= */

app.patch(
  "/api/admin/orders/:id/status",
  authenticateAdmin,
  async (req, res) => {
    try {
      const orderId = req.params.id;
      const status = String(
        req.body.status || ""
      ).trim();

      if (!status) {
        return res.status(400).json({
          success: false,
          message: "Sipariş durumu gereklidir.",
        });
      }

      const { data, error } =
        await supabase
          .from("orders")
          .update({
            status,
          })
          .eq("id", orderId)
          .select("*")
          .single();

      if (error) {
        console.error(
          "Order status update hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Sipariş durumu güncellenemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Sipariş durumu güncellendi.",
        order: data,
      });
    } catch (error) {
      console.error(
        "Order status genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   ADMIN ORDER DELETE
========================================================= */

app.delete(
  "/api/admin/orders/:id",
  authenticateAdmin,
  async (req, res) => {
    try {
      const orderId = req.params.id;

      const { error } =
        await supabase
          .from("orders")
          .delete()
          .eq("id", orderId);

      if (error) {
        console.error(
          "Order delete hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Sipariş silinemedi.",
        });
      }

      return res.json({
        success: true,
        message: "Sipariş silindi.",
      });
    } catch (error) {
      console.error(
        "Order delete genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   SİPARİŞ OLUŞTUR
   NOT:
   customerPhone BURADA BIRAKILDI.
   Çünkü sipariş teslimatı için gerekli olabilir.
========================================================= */

async function sendOrderEmail(order) {
  const adminEmail =
    process.env.BREVO_SENDER_EMAIL;

  if (!adminEmail) {
    console.warn(
      "BREVO_SENDER_EMAIL bulunamadı, sipariş e-postası gönderilmedi."
    );
    return;
  }

  const customerName =
    order.customerName || "Müşteri";

  const customerEmail =
    order.customerEmail || "";

  const customerPhone =
    order.customerPhone || "";

  const address =
    order.address || "";

  const total =
    order.total || 0;

  const items = Array.isArray(order.items)
    ? order.items
    : [];

  const itemsHtml = items
    .map((item) => {
      const name =
        item.name || item.title || "Ürün";

      const quantity =
        item.quantity || 1;

      const price =
        item.price || 0;

      return `
        <tr>
          <td style="padding:10px;border-bottom:1px solid #ddd;">
            ${name}
          </td>
          <td style="padding:10px;border-bottom:1px solid #ddd;text-align:center;">
            ${quantity}
          </td>
          <td style="padding:10px;border-bottom:1px solid #ddd;text-align:right;">
            ${price} TL
          </td>
        </tr>
      `;
    })
    .join("");

  await sendBrevoEmail({
    to: adminEmail,
    subject: `VELORA Yeni Sipariş - ${customerName}`,
    htmlContent: `
      <div style="font-family:Arial,sans-serif;max-width:700px;margin:auto;padding:30px;">
        <h1 style="letter-spacing:4px;">VELORA</h1>

        <h2>Yeni Sipariş</h2>

        <p><strong>Müşteri:</strong> ${customerName}</p>
        <p><strong>E-posta:</strong> ${customerEmail}</p>
        <p><strong>Telefon:</strong> ${customerPhone}</p>
        <p><strong>Adres:</strong> ${address}</p>

        <h3>Ürünler</h3>

        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr>
              <th style="padding:10px;text-align:left;">Ürün</th>
              <th style="padding:10px;">Adet</th>
              <th style="padding:10px;text-align:right;">Fiyat</th>
            </tr>
          </thead>

          <tbody>
            ${itemsHtml}
          </tbody>
        </table>

        <h2 style="text-align:right;margin-top:25px;">
          Toplam: ${total} TL
        </h2>
      </div>
    `,
  });
}

app.post(
  "/api/order",
  async (req, res) => {
    try {
      const {
        userId,
        customerName,
        customerEmail,
        customerPhone,
        address,
        items,
        total,
      } = req.body;

      if (
        !customerName ||
        !customerEmail ||
        !customerPhone ||
        !address ||
        !Array.isArray(items) ||
        items.length === 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Sipariş için gerekli alanlar eksik.",
        });
      }

      const orderData = {
        user_id: userId || null,
        customer_name: customerName,
        customer_email: normalizeEmail(
          customerEmail
        ),
        customer_phone: customerPhone,
        address,
        items,
        total: Number(total) || 0,
        status: "Yeni Sipariş",
      };

      const { data: order, error } =
        await supabase
          .from("orders")
          .insert(orderData)
          .select("*")
          .single();

      if (error) {
        console.error(
          "Sipariş oluşturma hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Sipariş oluşturulamadı.",
        });
      }

      try {
        await sendOrderEmail({
          customerName,
          customerEmail,
          customerPhone,
          address,
          items,
          total,
        });
      } catch (mailError) {
        console.error(
          "Sipariş e-postası gönderilemedi:",
          mailError
        );
      }

      return res.status(201).json({
        success: true,
        message: "Siparişiniz başarıyla oluşturuldu.",
        order,
      });
    } catch (error) {
      console.error(
        "Order genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Sunucu hatası.",
      });
    }
  }
);

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Endpoint bulunamadı.",
  });
});

/* =========================================================
   SERVER
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `VELORA backend ${PORT} portunda çalışıyor.`
  );
});
