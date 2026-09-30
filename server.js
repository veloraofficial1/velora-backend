```js
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
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS",
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],
  })
);

const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME;

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD;

const SUPABASE_URL =
  process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);


// ======================================================
// YARDIMCI FONKSİYONLAR
// ======================================================

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}


function generateVerificationCode() {
  return crypto
    .randomInt(100000, 1000000)
    .toString();
}


function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


function normalizeUsername(username) {
  return String(username || "")
    .trim();
}


// ======================================================
// KULLANICI AUTH MIDDLEWARE
// ======================================================

function authMiddleware(req, res, next) {
  try {
    const authHeader =
      req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message:
          "Giriş yapmanız gerekiyor.",
      });
    }

    const token =
      authHeader.startsWith("Bearer ")
        ? authHeader.substring(7)
        : authHeader;

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = decoded;

    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message:
        "Geçersiz veya süresi dolmuş oturum.",
    });
  }
}


// ======================================================
// BREVO EMAIL
// ======================================================

async function sendEmail({
  to,
  subject,
  html,
}) {
  const apiKey =
    process.env.BREVO_API_KEY;

  const senderEmail =
    process.env.BREVO_SENDER_EMAIL;

  const senderName =
    process.env.BREVO_SENDER_NAME ||
    "VELORA";

  if (
    !apiKey ||
    !senderEmail
  ) {
    console.log(
      "Brevo ayarları bulunamadı. E-posta gönderilemedi."
    );

    return false;
  }

  try {
    const response =
      await fetch(
        "https://api.brevo.com/v3/smtp/email",
        {
          method: "POST",

          headers: {
            accept:
              "application/json",

            "api-key":
              apiKey,

            "content-type":
              "application/json",
          },

          body: JSON.stringify({
            sender: {
              name:
                senderName,

              email:
                senderEmail,
            },

            to: [
              {
                email: to,
              },
            ],

            subject,

            htmlContent:
              html,
          }),
        }
      );

    if (!response.ok) {
      const text =
        await response.text();

      console.error(
        "Brevo email hatası:",
        text
      );

      return false;
    }

    return true;

  } catch (error) {
    console.error(
      "Email gönderme hatası:",
      error
    );

    return false;
  }
}


// ======================================================
// ANA SAYFA
// ======================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message:
      "VELORA backend çalışıyor.",
  });
});


// ======================================================
// HEALTH
// ======================================================

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      success: true,
      message:
        "VELORA API çalışıyor.",
    });
  }
);


// ======================================================
// REGISTER
// ======================================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const {
        username,
        email,
        password,
        passwordConfirm,
      } = req.body;

      const cleanUsername =
        normalizeUsername(
          username
        );

      const cleanEmail =
        normalizeEmail(
          email
        );

      if (
        !cleanUsername ||
        !cleanEmail ||
        !password ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Lütfen tüm alanları doldurun.",
        });
      }

      if (
        cleanUsername.length < 3
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Kullanıcı adı en az 3 karakter olmalıdır.",
        });
      }

      if (
        password.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalıdır.",
        });
      }

      if (
        password !==
        passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Şifreler eşleşmiyor.",
        });
      }

      const {
        data: usernameUser,
        error: usernameError,
      } =
        await supabase
          .from("users")
          .select("id")
          .eq(
            "username",
            cleanUsername
          )
          .maybeSingle();

      if (usernameError) {
        console.error(
          "Username kontrol hatası:",
          usernameError
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı kontrolü sırasında hata oluştu.",
        });
      }

      if (usernameUser) {
        return res.status(400).json({
          success: false,
          message:
            "Bu kullanıcı adı zaten kullanılıyor.",
        });
      }

      const {
        data: emailUser,
        error: emailError,
      } =
        await supabase
          .from("users")
          .select("id")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (emailError) {
        console.error(
          "Email kontrol hatası:",
          emailError
        );

        return res.status(500).json({
          success: false,
          message:
            "E-posta kontrolü sırasında hata oluştu.",
        });
      }

      if (emailUser) {
        return res.status(400).json({
          success: false,
          message:
            "Bu e-posta adresi zaten kullanılıyor.",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          10
        );

      const verificationCode =
        generateVerificationCode();

      const verificationExpiresAt =
        new Date(
          Date.now() +
            15 * 60 * 1000
        ).toISOString();

      const {
        data: user,
        error: insertError,
      } =
        await supabase
          .from("users")
          .insert({
            username:
              cleanUsername,

            email:
              cleanEmail,

            password_hash:
              passwordHash,

            email_verified:
              false,

            verification_code:
              verificationCode,

            verification_expires_at:
              verificationExpiresAt,
          })
          .select()
          .single();

      if (insertError) {
        console.error(
          "Kullanıcı oluşturma Supabase hatası:",
          insertError
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı oluşturulamadı: " +
            (
              insertError.message ||
              "Bilinmeyen Supabase hatası"
            ),

          code:
            insertError.code ||
            null,

          details:
            insertError.details ||
            null,

          hint:
            insertError.hint ||
            null,
        });
      }

      const emailSent =
        await sendEmail({
          to: cleanEmail,

          subject:
            "VELORA - E-posta Doğrulama",

          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
              <h1 style="color:#9b7445;">VELORA</h1>

              <h2>E-posta Doğrulama</h2>

              <p>Merhaba ${cleanUsername},</p>

              <p>
                VELORA hesabınızı doğrulamak için aşağıdaki kodu kullanın:
              </p>

              <div style="
                font-size:32px;
                font-weight:bold;
                letter-spacing:8px;
                padding:20px;
                background:#f7f1e7;
                text-align:center;
                color:#4c3b2b;
              ">
                ${verificationCode}
              </div>

              <p>
                Bu kod 15 dakika boyunca geçerlidir.
              </p>

              <p>
                VELORA
              </p>
            </div>
          `,
        });

      return res.status(201).json({
        success: true,

        message:
          emailSent
            ? "Hesabınız oluşturuldu. E-posta adresinize gönderilen doğrulama kodunu girin."
            : "Hesabınız oluşturuldu ancak doğrulama e-postası gönderilemedi. Lütfen tekrar deneyin.",

        user: {
          id:
            user.id,

          username:
            user.username,

          email:
            user.email,
        },
      });

    } catch (error) {
      console.error(
        "Register genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcı oluşturulamadı: " +
          (
            error.message ||
            "Bilinmeyen hata"
          ),
      });
    }
  }
);


// ======================================================
// EMAIL VERIFY
// ======================================================

app.post(
  "/api/auth/verify-email",
  async (req, res) => {
    try {
      const {
        email,
        code,
      } = req.body;

      const cleanEmail =
        normalizeEmail(email);

      const cleanCode =
        String(code || "")
          .trim();

      if (
        !cleanEmail ||
        !cleanCode
      ) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta ve doğrulama kodu gereklidir.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (error) {
        console.error(
          "Verify kullanıcı hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Doğrulama sırasında hata oluştu.",
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı.",
        });
      }

      if (
        user.email_verified
      ) {
        return res.json({
          success: true,
          message:
            "E-posta adresiniz zaten doğrulanmış.",
        });
      }

      if (
        user.verification_code !==
        cleanCode
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Doğrulama kodu yanlış.",
        });
      }

      if (
        user.verification_expires_at &&
        new Date(
          user.verification_expires_at
        ) < new Date()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Doğrulama kodunun süresi dolmuş.",
        });
      }

      const {
        error: updateError,
      } =
        await supabase
          .from("users")
          .update({
            email_verified:
              true,

            verification_code:
              null,

            verification_expires_at:
              null,
          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {
        console.error(
          "Verify update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "E-posta doğrulanamadı.",
        });
      }

      return res.json({
        success: true,
        message:
          "E-posta adresiniz başarıyla doğrulandı.",
      });

    } catch (error) {
      console.error(
        "Verify genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Doğrulama sırasında hata oluştu.",
      });
    }
  }
);


// ======================================================
// RESEND VERIFICATION
// ======================================================

app.post(
  "/api/auth/resend-verification",
  async (req, res) => {
    try {
      const {
        email,
      } = req.body;

      const cleanEmail =
        normalizeEmail(email);

      if (!cleanEmail) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta adresi gereklidir.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (error) {
        console.error(
          "Resend kullanıcı hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bulunamadı.",
        });
      }

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı.",
        });
      }

      if (
        user.email_verified
      ) {
        return res.json({
          success: true,
          message:
            "E-posta adresiniz zaten doğrulanmış.",
        });
      }

      const verificationCode =
        generateVerificationCode();

      const verificationExpiresAt =
        new Date(
          Date.now() +
            15 * 60 * 1000
        ).toISOString();

      const {
        error: updateError,
      } =
        await supabase
          .from("users")
          .update({
            verification_code:
              verificationCode,

            verification_expires_at:
              verificationExpiresAt,
          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {
        console.error(
          "Resend update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Yeni doğrulama kodu oluşturulamadı.",
        });
      }

      const emailSent =
        await sendEmail({
          to: cleanEmail,

          subject:
            "VELORA - Yeni Doğrulama Kodu",

          html: `
            <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
              <h1 style="color:#9b7445;">VELORA</h1>

              <h2>Yeni Doğrulama Kodunuz</h2>

              <p>Merhaba ${user.username},</p>

              <div style="
                font-size:32px;
                font-weight:bold;
                letter-spacing:8px;
                padding:20px;
                background:#f7f1e7;
                text-align:center;
                color:#4c3b2b;
              ">
                ${verificationCode}
              </div>

              <p>
                Bu kod 15 dakika boyunca geçerlidir.
              </p>
            </div>
          `,
        });

      return res.json({
        success: true,

        message:
          emailSent
            ? "Yeni doğrulama kodu e-posta adresinize gönderildi."
            : "Kod oluşturuldu ancak e-posta gönderilemedi.",
      });

    } catch (error) {
      console.error(
        "Resend genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Yeni doğrulama kodu gönderilemedi.",
      });
    }
  }
);


// ======================================================
// LOGIN
// ======================================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const {
        email,
        password,
      } = req.body;

      const cleanEmail =
        normalizeEmail(email);

      if (
        !cleanEmail ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta ve şifre gereklidir.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (error) {
        console.error(
          "Login Supabase hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Giriş sırasında hata oluştu.",
        });
      }

      if (!user) {
        return res.status(401).json({
          success: false,
          message:
            "E-posta veya şifre hatalı.",
        });
      }

      const passwordMatch =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordMatch) {
        return res.status(401).json({
          success: false,
          message:
            "E-posta veya şifre hatalı.",
        });
      }

      if (
        user.email_verified ===
        false
      ) {
        return res.status(403).json({
          success: false,

          message:
            "Lütfen önce e-posta adresinizi doğrulayın.",

          emailVerified:
            false,
        });
      }

      const token =
        createToken(user);

      return res.json({
        success: true,

        message:
          "Giriş başarılı.",

        token,

        user: {
          id:
            user.id,

          username:
            user.username,

          email:
            user.email,
        },
      });

    } catch (error) {
      console.error(
        "Login genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Giriş yapılamadı.",
      });
    }
  }
);


// ======================================================
// FORGOT PASSWORD
// ======================================================

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {
    try {
      const {
        email,
      } = req.body;

      const cleanEmail =
        normalizeEmail(email);

      if (!cleanEmail) {
        return res.status(400).json({
          success: false,
          message:
            "E-posta adresi gereklidir.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (error) {
        console.error(
          "Forgot password hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "İşlem sırasında hata oluştu.",
        });
      }

      if (!user) {
        return res.json({
          success: true,
          message:
            "Eğer bu e-posta kayıtlıysa şifre sıfırlama kodu gönderildi.",
        });
      }

      const resetCode =
        generateVerificationCode();

      const resetExpiresAt =
        new Date(
          Date.now() +
            15 * 60 * 1000
        ).toISOString();

      const {
        error: updateError,
      } =
        await supabase
          .from("users")
          .update({
            verification_code:
              resetCode,

            verification_expires_at:
              resetExpiresAt,
          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {
        console.error(
          "Forgot update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre sıfırlama kodu oluşturulamadı.",
        });
      }

      await sendEmail({
        to: cleanEmail,

        subject:
          "VELORA - Şifre Sıfırlama",

        html: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
            <h1 style="color:#9b7445;">VELORA</h1>

            <h2>Şifre Sıfırlama</h2>

            <p>Merhaba ${user.username},</p>

            <p>
              Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:
            </p>

            <div style="
              font-size:32px;
              font-weight:bold;
              letter-spacing:8px;
              padding:20px;
              background:#f7f1e7;
              text-align:center;
              color:#4c3b2b;
            ">
              ${resetCode}
            </div>

            <p>
              Bu kod 15 dakika boyunca geçerlidir.
            </p>
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
        "Forgot genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlama işlemi başarısız.",
      });
    }
  }
);


// ======================================================
// RESET PASSWORD
// ======================================================

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    try {
      const {
        email,
        code,
        newPassword,
        passwordConfirm,
      } = req.body;

      const cleanEmail =
        normalizeEmail(email);

      const cleanCode =
        String(code || "")
          .trim();

      if (
        !cleanEmail ||
        !cleanCode ||
        !newPassword ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Lütfen tüm alanları doldurun.",
        });
      }

      if (
        newPassword.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalıdır.",
        });
      }

      if (
        newPassword !==
        passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Şifreler eşleşmiyor.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            cleanEmail
          )
          .maybeSingle();

      if (
        error ||
        !user
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Geçersiz bilgiler.",
        });
      }

      if (
        user.verification_code !==
        cleanCode
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Kod yanlış.",
        });
      }

      if (
        user.verification_expires_at &&
        new Date(
          user.verification_expires_at
        ) < new Date()
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Kodun süresi dolmuş.",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          newPassword,
          10
        );

      const {
        error: updateError,
      } =
        await supabase
          .from("users")
          .update({
            password_hash:
              passwordHash,

            verification_code:
              null,

            verification_expires_at:
              null,
          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {
        console.error(
          "Reset update hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre değiştirilemedi.",
        });
      }

      return res.json({
        success: true,
        message:
          "Şifreniz başarıyla değiştirildi.",
      });

    } catch (error) {
      console.error(
        "Reset genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre sıfırlama başarısız.",
      });
    }
  }
);


// ======================================================
// CHANGE PASSWORD
// ======================================================

app.post(
  "/api/auth/change-password",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        currentPassword,
        newPassword,
        passwordConfirm,
      } = req.body;

      if (
        !currentPassword ||
        !newPassword ||
        !passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Lütfen tüm alanları doldurun.",
        });
      }

      if (
        newPassword.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre en az 6 karakter olmalıdır.",
        });
      }

      if (
        newPassword !==
        passwordConfirm
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Yeni şifreler eşleşmiyor.",
        });
      }

      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "id",
            req.user.id
          )
          .maybeSingle();

      if (
        error ||
        !user
      ) {
        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı.",
        });
      }

      const passwordMatch =
        await bcrypt.compare(
          currentPassword,
          user.password_hash
        );

      if (!passwordMatch) {
        return res.status(400).json({
          success: false,
          message:
            "Mevcut şifreniz yanlış.",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          newPassword,
          10
        );

      const {
        error: updateError,
      } =
        await supabase
          .from("users")
          .update({
            password_hash:
              passwordHash,
          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {
        console.error(
          "Change password hatası:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre değiştirilemedi.",
        });
      }

      return res.json({
        success: true,
        message:
          "Şifreniz başarıyla değiştirildi.",
      });

    } catch (error) {
      console.error(
        "Change password genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Şifre değiştirilemedi.",
      });
    }
  }
);


// ======================================================
// ME
// ======================================================

app.get(
  "/api/auth/me",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        data: user,
        error,
      } =
        await supabase
          .from("users")
          .select(
            "id, username, email, email_verified"
          )
          .eq(
            "id",
            req.user.id
          )
          .maybeSingle();

      if (
        error ||
        !user
      ) {
        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı.",
        });
      }

      return res.json({
        success: true,
        user,
      });

    } catch (error) {
      console.error(
        "Me hatası:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcı bilgileri alınamadı.",
      });
    }
  }
);


// ======================================================
// FAVORITES GET
// ======================================================

app.get(
  "/api/favorites",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        data,
        error,
      } =
        await supabase
          .from("favorites")
          .select("*")
          .eq(
            "user_id",
            req.user.id
          );

      if (error) {
        console.error(
          "Favorites GET hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Favoriler alınamadı.",
        });
      }

      return res.json({
        success: true,
        favorites:
          data || [],
      });

    } catch (error) {
      console.error(
        "Favorites GET genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Favoriler alınamadı.",
      });
    }
  }
);


// ======================================================
// FAVORITES ADD
// ======================================================

app.post(
  "/api/favorites",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        productId,
      } = req.body;

      if (!productId) {
        return res.status(400).json({
          success: false,
          message:
            "Ürün ID gereklidir.",
        });
      }

      const {
        data,
        error,
      } =
        await supabase
          .from("favorites")
          .upsert(
            {
              user_id:
                req.user.id,

              product_id:
                productId,
            },
            {
              onConflict:
                "user_id,product_id",
            }
          )
          .select()
          .single();

      if (error) {
        console.error(
          "Favorite add hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Favorilere eklenemedi.",
        });
      }

      return res.json({
        success: true,
        favorite: data,
      });

    } catch (error) {
      console.error(
        "Favorite add genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Favorilere eklenemedi.",
      });
    }
  }
);


// ======================================================
// FAVORITES DELETE
// ======================================================

app.delete(
  "/api/favorites/:productId",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        productId,
      } = req.params;

      const {
        error,
      } =
        await supabase
          .from("favorites")
          .delete()
          .eq(
            "user_id",
            req.user.id
          )
          .eq(
            "product_id",
            productId
          );

      if (error) {
        console.error(
          "Favorite delete hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Favorilerden kaldırılamadı.",
        });
      }

      return res.json({
        success: true,
        message:
          "Favorilerden kaldırıldı.",
      });

    } catch (error) {
      console.error(
        "Favorite delete genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Favorilerden kaldırılamadı.",
      });
    }
  }
);


// ======================================================
// SİPARİŞ DURUMLARI
// ======================================================

const VALID_ORDER_STATUSES = [
  "pending",
  "preparing",
  "shipped",
  "out_for_delivery",
  "delivered",
  "cancelled",
];


// Eski kayıtlarla uyumluluk
function normalizeOrderStatus(status) {
  const value =
    String(status || "")
      .trim();

  const statusMap = {
    Yeni:
      "pending",

    "Sipariş Alındı":
      "pending",

    pending:
      "pending",

    "Hazırlanıyor":
      "preparing",

    preparing:
      "preparing",

    Kargoda:
      "shipped",

    "Kargoya Verildi":
      "shipped",

    shipped:
      "shipped",

    Dağıtımda:
      "out_for_delivery",

    out_for_delivery:
      "out_for_delivery",

    "Teslim Edildi":
      "delivered",

    delivered:
      "delivered",

    İptal:
      "cancelled",

    "İptal Edildi":
      "cancelled",

    cancelled:
      "cancelled",
  };

  return (
    statusMap[value] ||
    "pending"
  );
}


// ======================================================
// ORDERS - USER
// ======================================================

app.get(
  "/api/orders/my",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        data,
        error,
      } =
        await supabase
          .from("orders")
          .select("*")
          .eq(
            "user_id",
            req.user.id
          )
          .order(
            "created_at",
            {
              ascending:
                false,
            }
          );

      if (error) {
        console.error(
          "Orders GET hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Siparişler alınamadı.",
        });
      }

      const orders =
        (data || []).map(
          (order) => ({
            ...order,

            status:
              normalizeOrderStatus(
                order.status
              ),
          })
        );

      return res.json({
        success: true,
        orders,
      });

    } catch (error) {
      console.error(
        "Orders GET genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Siparişler alınamadı.",
      });
    }
  }
);


// ======================================================
// ORDER CREATE
// ======================================================
//
// ÖNEMLİ:
// Artık userId frontend'den alınmıyor.
// Sipariş doğrudan JWT içindeki req.user.id
// ile giriş yapan hesaba bağlanıyor.
// ======================================================

app.post(
  "/api/orders",
  authMiddleware,
  async (req, res) => {
    try {
      const {
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
        items.length === 0 ||
        total === undefined
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Sipariş bilgileri eksik.",
        });
      }


      // ==================================================
      // SİPARİŞİ SUPABASE'E KAYDET
      // ==================================================

      const {
        data: order,
        error,
      } =
        await supabase
          .from("orders")
          .insert({
            // KRİTİK:
            // Frontend'den gelen userId kullanılmıyor.
            user_id:
              req.user.id,

            customer_name:
              customerName,

            customer_email:
              customerEmail,

            customer_phone:
              customerPhone,

            address,

            items,

            total:
              Number(total) || 0,

            status:
              "pending",
          })
          .select()
          .single();


      if (error) {
        console.error(
          "Order oluşturma hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Sipariş oluşturulamadı: " +
            (
              error.message ||
              "Bilinmeyen hata"
            ),
        });
      }


      console.log(
        "Yeni sipariş oluşturuldu:",
        order.id,
        "Kullanıcı:",
        req.user.id
      );


      // ==================================================
      // ÜRÜNLERİ HTML'E ÇEVİR
      // ==================================================

      const itemsHtml =
        items
          .map(
            (item) => {
              const productName =
                item.name ||
                item.productName ||
                `Ürün #${
                  item.productId ||
                  ""
                }`;

              const quantity =
                item.quantity ||
                1;

              const price =
                item.price !==
                  undefined &&
                item.price !==
                  null
                  ? `${item.price} TL`
                  : "Fiyat belirtilmemiş";

              return `
                <tr>

                  <td style="
                    padding:12px;
                    border-bottom:1px solid #ddd;
                  ">
                    ${productName}
                  </td>

                  <td style="
                    padding:12px;
                    border-bottom:1px solid #ddd;
                    text-align:center;
                  ">
                    ${quantity}
                  </td>

                  <td style="
                    padding:12px;
                    border-bottom:1px solid #ddd;
                    text-align:right;
                  ">
                    ${price}
                  </td>

                </tr>
              `;
            }
          )
          .join("");


      // ==================================================
      // MÜŞTERİYE MAİL
      // ==================================================

      const customerEmailSent =
        await sendEmail({
          to:
            customerEmail,

          subject:
            "VELORA - Siparişiniz Alındı",

          html: `
            <div style="
              font-family:Arial,sans-serif;
              max-width:700px;
              margin:auto;
              padding:30px;
              color:#4c3b2b;
            ">

              <h1 style="
                color:#9b7445;
              ">
                VELORA
              </h1>

              <h2>
                Siparişiniz Alındı
              </h2>

              <p>
                Merhaba ${customerName},
              </p>

              <p>
                Siparişiniz başarıyla oluşturuldu.
              </p>

              <hr>

              <p>
                <strong>Sipariş ID:</strong>
                ${order.id}
              </p>

              <p>
                <strong>Telefon:</strong>
                ${customerPhone}
              </p>

              <p>
                <strong>Adres:</strong><br>
                ${address}
              </p>

              <p>
                <strong>Toplam:</strong>
                ${total} TL
              </p>

              <p>
                <strong>Durum:</strong>
                Sipariş Alındı
              </p>

              <hr>

              <p>
                VELORA
              </p>

            </div>
          `,
        });


      console.log(
        "Müşteri maili gönderildi:",
        customerEmailSent
      );


      // ==================================================
      // YÖNETİCİ MAİLİ
      // ==================================================

      const adminEmail =
        process.env.ADMIN_EMAIL;

      let adminEmailSent =
        false;


      if (!adminEmail) {

        console.error(
          "ADMIN_EMAIL environment variable bulunamadı!"
        );

      } else {

        adminEmailSent =
          await sendEmail({

            to:
              adminEmail,

            subject:
              `VELORA - Yeni Sipariş #${order.id}`,

            html: `
              <div style="
                font-family:Arial,sans-serif;
                max-width:750px;
                margin:auto;
                padding:30px;
                color:#4c3b2b;
              ">

                <h1 style="
                  color:#9b7445;
                  margin-bottom:5px;
                ">
                  VELORA
                </h1>

                <h2>
                  Yeni Sipariş Alındı
                </h2>

                <p style="
                  background:#f7f1e7;
                  padding:15px;
                  border-left:4px solid #9b7445;
                ">
                  Yeni bir müşteri siparişi oluşturuldu.
                </p>

                <hr>

                <h3>
                  Sipariş Bilgileri
                </h3>

                <p>
                  <strong>Sipariş ID:</strong>
                  ${order.id}
                </p>

                <p>
                  <strong>Durum:</strong>
                  Sipariş Alındı
                </p>

                <p>
                  <strong>Tarih:</strong>
                  ${new Date()
                    .toLocaleString(
                      "tr-TR"
                    )}
                </p>

                <hr>

                <h3>
                  Müşteri Bilgileri
                </h3>

                <p>
                  <strong>Ad Soyad:</strong>
                  ${customerName}
                </p>

                <p>
                  <strong>E-posta:</strong>
                  ${customerEmail}
                </p>

                <p>
                  <strong>Telefon:</strong>
                  ${customerPhone}
                </p>

                <p>
                  <strong>Adres:</strong><br>
                  ${address}
                </p>

                <hr>

                <h3>
                  Sipariş Detayları
                </h3>

                <table style="
                  width:100%;
                  border-collapse:collapse;
                ">

                  <thead>

                    <tr>

                      <th style="
                        padding:12px;
                        background:#f7f1e7;
                        text-align:left;
                      ">
                        Ürün
                      </th>

                      <th style="
                        padding:12px;
                        background:#f7f1e7;
                        text-align:center;
                      ">
                        Adet
                      </th>

                      <th style="
                        padding:12px;
                        background:#f7f1e7;
                        text-align:right;
                      ">
                        Fiyat
                      </th>

                    </tr>

                  </thead>

                  <tbody>

                    ${itemsHtml}

                  </tbody>

                </table>

                <div style="
                  margin-top:25px;
                  padding:18px;
                  background:#f7f1e7;
                  text-align:right;
                  font-size:20px;
                ">

                  <strong>
                    Toplam: ${total} TL
                  </strong>

                </div>

                <hr>

                <p style="
                  font-size:13px;
                  color:#777;
                ">
                  Bu mail VELORA yönetici sipariş
                  bildirim sisteminden otomatik olarak
                  gönderilmiştir.
                </p>

              </div>
            `,
          });

        console.log(
          "Yönetici maili gönderildi:",
          adminEmailSent
        );
      }


      // ==================================================
      // BAŞARILI CEVAP
      // ==================================================

      return res.status(201).json({
        success:
          true,

        message:
          "Siparişiniz başarıyla oluşturuldu.",

        order,

        customerEmailSent:
          customerEmailSent,

        adminEmailSent:
          adminEmailSent,
      });

    } catch (error) {

      console.error(
        "Order genel hata:",
        error
      );

      return res.status(500).json({
        success:
          false,

        message:
          "Sipariş oluşturulamadı.",

        error:
          error.message ||
          "Bilinmeyen hata",
      });
    }
  }
);


// ======================================================
// ADMIN LOGIN
// ======================================================

app.post(
  "/api/admin/login",
  async (req, res) => {
    try {
      const {
        username,
        password,
      } = req.body;

      if (
        username !==
          ADMIN_USERNAME ||
        password !==
          ADMIN_PASSWORD
      ) {
        return res.status(401).json({
          success: false,
          message:
            "Admin kullanıcı adı veya şifre hatalı.",
        });
      }

      const token =
        jwt.sign(
          {
            admin:
              true,

            username,
          },
          JWT_SECRET,
          {
            expiresIn:
              "7d",
          }
        );

      return res.json({
        success:
          true,

        message:
          "Admin girişi başarılı.",

        token,
      });

    } catch (error) {
      console.error(
        "Admin login hatası:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Admin girişi yapılamadı.",
      });
    }
  }
);


// ======================================================
// ADMIN MIDDLEWARE
// ======================================================

function adminMiddleware(
  req,
  res,
  next
) {
  try {
    const authHeader =
      req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message:
          "Admin girişi gerekiyor.",
      });
    }

    const token =
      authHeader.startsWith(
        "Bearer "
      )
        ? authHeader.substring(
            7
          )
        : authHeader;

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if (!decoded.admin) {
      return res.status(403).json({
        success: false,
        message:
          "Admin yetkisi gerekiyor.",
      });
    }

    req.admin =
      decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      success: false,
      message:
        "Geçersiz admin oturumu.",
    });

  }
}


// ======================================================
// ADMIN STATS
// ======================================================

app.get(
  "/api/admin/stats",
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        count: usersCount,
        error: usersError,
      } =
        await supabase
          .from("users")
          .select("*", {
            count:
              "exact",
            head:
              true,
          });

      const {
        count: ordersCount,
        error: ordersError,
      } =
        await supabase
          .from("orders")
          .select("*", {
            count:
              "exact",
            head:
              true,
          });

      if (
        usersError ||
        ordersError
      ) {
        console.error(
          "Stats hatası:",
          usersError ||
            ordersError
        );

        return res.status(500).json({
          success: false,
          message:
            "İstatistikler alınamadı.",
        });
      }

      return res.json({
        success:
          true,

        stats: {
          users:
            usersCount || 0,

          orders:
            ordersCount || 0,
        },
      });

    } catch (error) {
      console.error(
        "Stats genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "İstatistikler alınamadı.",
      });
    }
  }
);


// ======================================================
// ADMIN USERS
// ======================================================

app.get(
  "/api/admin/users",
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        data,
        error,
      } =
        await supabase
          .from("users")
          .select(
            "id, username, email, email_verified"
          )
          .order(
            "id",
            {
              ascending:
                false,
            }
          );

      if (error) {
        console.error(
          "Admin users hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcılar alınamadı.",
        });
      }

      return res.json({
        success:
          true,

        users:
          data || [],
      });

    } catch (error) {
      console.error(
        "Admin users genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcılar alınamadı.",
      });
    }
  }
);


// ======================================================
// ADMIN USER DELETE
// ======================================================

app.delete(
  "/api/admin/users/:id",
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        id,
      } = req.params;

      const {
        error,
      } =
        await supabase
          .from("users")
          .delete()
          .eq(
            "id",
            id
          );

      if (error) {
        console.error(
          "Admin user delete hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı silinemedi.",
        });
      }

      return res.json({
        success:
          true,

        message:
          "Kullanıcı silindi.",
      });

    } catch (error) {
      console.error(
        "Admin user delete genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcı silinemedi.",
      });
    }
  }
);


// ======================================================
// ADMIN ORDERS
// ======================================================

app.get(
  "/api/admin/orders",
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        data,
        error,
      } =
        await supabase
          .from("orders")
          .select("*")
          .order(
            "created_at",
            {
              ascending:
                false,
            }
          );

      if (error) {
        console.error(
          "Admin orders hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Siparişler alınamadı.",
        });
      }

      const orders =
        (data || []).map(
          (order) => ({
            ...order,

            status:
              normalizeOrderStatus(
                order.status
              ),
          })
        );


      return res.json({
        success:
          true,

        orders,
      });

    } catch (error) {
      console.error(
        "Admin orders genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Siparişler alınamadı.",
      });
    }
  }
);


// ======================================================
// ADMIN ORDER STATUS UPDATE
// PUT + PATCH
// ======================================================

async function updateAdminOrderStatus(
  req,
  res
) {
  try {
    const {
      id,
    } = req.params;

    const {
      status,
    } = req.body;


    if (!status) {
      return res.status(400).json({
        success:
          false,

        message:
          "Durum gereklidir.",
      });
    }


    const normalizedStatus =
      normalizeOrderStatus(
        status
      );


    if (
      !VALID_ORDER_STATUSES.includes(
        normalizedStatus
      )
    ) {
      return res.status(400).json({
        success:
          false,

        message:
          "Geçersiz sipariş durumu.",
      });
    }


    const {
      data,
      error,
    } =
      await supabase
        .from("orders")
        .update({
          status:
            normalizedStatus,
        })
        .eq(
          "id",
          id
        )
        .select()
        .single();


    if (error) {
      console.error(
        "Order status hatası:",
        error
      );

      return res.status(500).json({
        success:
          false,

        message:
          "Sipariş durumu güncellenemedi.",
      });
    }


    return res.json({
      success:
        true,

      message:
        "Sipariş durumu güncellendi.",

      order:
        data,
    });

  } catch (error) {

    console.error(
      "Order status genel hata:",
      error
    );

    return res.status(500).json({
      success:
        false,

      message:
        "Sipariş durumu güncellenemedi.",
    });
  }
}


// PUT
app.put(
  "/api/admin/orders/:id/status",
  adminMiddleware,
  updateAdminOrderStatus
);


// PATCH
app.patch(
  "/api/admin/orders/:id/status",
  adminMiddleware,
  updateAdminOrderStatus
);


// ======================================================
// ADMIN ORDER DELETE
// ======================================================

app.delete(
  "/api/admin/orders/:id",
  adminMiddleware,
  async (req, res) => {
    try {
      const {
        id,
      } = req.params;

      const {
        error,
      } =
        await supabase
          .from("orders")
          .delete()
          .eq(
            "id",
            id
          );

      if (error) {
        console.error(
          "Admin order delete hatası:",
          error
        );

        return res.status(500).json({
          success:
            false,

          message:
            "Sipariş silinemedi.",
        });
      }

      return res.json({
        success:
          true,

        message:
          "Sipariş silindi.",
      });

    } catch (error) {

      console.error(
        "Admin order delete genel hata:",
        error
      );

      return res.status(500).json({
        success:
          false,

        message:
          "Sipariş silinemedi.",
      });
    }
  }
);


// ======================================================
// 404
// ======================================================

app.use(
  (req, res) => {
    res.status(404).json({
      success:
        false,

      message:
        "İstek yapılan adres bulunamadı.",
    });
  }
);


// ======================================================
// SERVER
// ======================================================

const PORT =
  process.env.PORT ||
  10000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `VELORA backend ${PORT} portunda çalışıyor.`
    );
  }
);
```
