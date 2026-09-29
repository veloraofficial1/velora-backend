require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const BREVO_API_KEY =
  process.env.BREVO_API_KEY || "";

const BREVO_SENDER_EMAIL =
  process.env.BREVO_SENDER_EMAIL || "";

const BREVO_SENDER_NAME =
  process.env.BREVO_SENDER_NAME || "VELORA";

const SUPABASE_URL =
  process.env.SUPABASE_URL;

const SUPABASE_SERVICE_ROLE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY;

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

if (!SUPABASE_URL) {
  console.error("SUPABASE_URL eksik!");
  process.exit(1);
}

if (!SUPABASE_SERVICE_ROLE_KEY) {
  console.error("SUPABASE_SERVICE_ROLE_KEY eksik!");
  process.exit(1);
}


/* =========================
   SUPABASE
========================= */

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY
);


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
    methods: [
      "GET",
      "POST",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

app.use(express.json());


/* =========================
   TOKEN
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


/* =========================
   PHONE NORMALIZE
========================= */

function normalizePhone(phone) {

  let cleanPhone =
    String(phone || "")
      .replace(/\D/g, "");

  /*
   * Eğer kullanıcı 905551234567
   * şeklinde gönderirse 05551234567
   * formatına çevir.
   */

  if (
    cleanPhone.startsWith("90") &&
    cleanPhone.length === 12
  ) {
    cleanPhone =
      "0" + cleanPhone.slice(2);
  }

  return cleanPhone;
}


/* =========================
   USER AUTH
========================= */

function authenticateUser(req, res, next) {

  const auth =
    req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {

    return res.status(401).json({
      success: false,
      message:
        "Yetkilendirme gerekli."
    });

  }

  const token =
    auth.substring(7);

  try {

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
        "Geçersiz veya süresi dolmuş token."
    });

  }
}


/* =========================
   ADMIN AUTH
========================= */

function authenticateAdmin(req, res, next) {

  const auth =
    req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {

    return res.status(401).json({
      success: false,
      message:
        "Admin girişi gerekli."
    });

  }

  const token =
    auth.substring(7);

  try {

    const decoded =
      jwt.verify(
        token,
        JWT_SECRET
      );

    if (
      decoded.role !== "admin"
    ) {

      return res.status(403).json({
        success: false,
        message:
          "Admin yetkisi gerekli."
      });

    }

    req.admin = decoded;

    next();

  } catch (error) {

    return res.status(401).json({
      success: false,
      message:
        "Geçersiz admin token."
    });

  }
}


/* =========================
   BREVO EMAIL
========================= */

async function sendBrevoEmail({
  to,
  subject,
  textContent
}) {

  if (!BREVO_API_KEY) {
    throw new Error(
      "BREVO_API_KEY eksik."
    );
  }

  if (!BREVO_SENDER_EMAIL) {
    throw new Error(
      "BREVO_SENDER_EMAIL eksik."
    );
  }

  const response =
    await fetch(
      "https://api.brevo.com/v3/smtp/email",
      {
        method: "POST",

        headers: {
          accept:
            "application/json",

          "api-key":
            BREVO_API_KEY,

          "content-type":
            "application/json"
        },

        body:
          JSON.stringify({
            sender: {
              name:
                BREVO_SENDER_NAME,

              email:
                BREVO_SENDER_EMAIL
            },

            to: [
              {
                email: to
              }
            ],

            subject:
              subject,

            textContent:
              textContent
          })
      }
    );

  if (!response.ok) {

    const text =
      await response.text();

    throw new Error(
      `Brevo hata: ${response.status} ${text}`
    );
  }

  return true;
}


/* =========================
   VERIFICATION EMAIL
========================= */

async function sendVerificationEmail(
  email,
  code
) {

  return sendBrevoEmail({

    to:
      email,

    subject:
      "VELORA E-posta Doğrulama Kodun",

    textContent:
`VELORA hesabını doğrulamak için kodun:

${code}

Bu kod 10 dakika geçerlidir.

Eğer bu işlemi sen yapmadıysan bu e-postayı dikkate alma.`
  });
}


/* =========================
   PASSWORD RESET EMAIL
========================= */

async function sendPasswordResetEmail(
  email,
  code
) {

  return sendBrevoEmail({

    to:
      email,

    subject:
      "VELORA Şifre Sıfırlama Kodu",

    textContent:
`VELORA şifreni sıfırlamak için kodun:

${code}

Bu kod 10 dakika geçerlidir.

Eğer bu işlemi sen yapmadıysan bu e-postayı dikkate alma.`
  });
}


/* =========================
   ANA SAYFA
========================= */

app.get(
  "/",
  (req, res) => {

    res.send(
      "VELORA backend çalışıyor! 🚀"
    );

  }
);


/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (req, res) => {

    res.json({
      success: true,
      message:
        "VELORA API aktif"
    });

  }
);


/* =========================
   REGISTER
========================= */

app.post(
  "/api/auth/register",
  async (req, res) => {

    try {

      const {
        username,
        email,
        phone,
        password,
        passwordConfirm
      } = req.body;


      const cleanUsername =
        String(
          username || ""
        ).trim();


      const cleanEmail =
        String(
          email || ""
        )
          .trim()
          .toLowerCase();


      /*
       * Telefonu temizle.
       * Örneğin:
       *
       * 0555 123 45 67
       * 05551234567
       * +90 555 123 45 67
       *
       * uygun şekilde 05551234567
       * haline getirilecek.
       */

      const cleanPhone =
        normalizePhone(phone);


      /* =========================
         REQUIRED CHECK
      ========================= */

      if (
        !cleanUsername ||
        !cleanEmail ||
        !cleanPhone ||
        !password ||
        !passwordConfirm
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Kullanıcı adı, e-posta, telefon, şifre ve şifre tekrarı gerekli."
        });

      }


      /* =========================
         PHONE FORMAT
      ========================= */

      if (
        !/^05[0-9]{9}$/.test(
          cleanPhone
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçerli bir telefon numarası girin. Örnek: 05551234567"
        });

      }


      /* =========================
         PASSWORD CHECK
      ========================= */

      if (
        password !==
        passwordConfirm
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Şifreler aynı değil."
        });

      }


      if (
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalı."
        });

      }


      /* =========================
         USERNAME CHECK
      ========================= */

      const {
        data: usernameUser,
        error: usernameError
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
          "USERNAME CHECK ERROR:",
          usernameError
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı kontrolü başarısız."
        });

      }


      if (usernameUser) {

        return res.status(409).json({
          success: false,
          message:
            "Bu kullanıcı adı zaten kayıtlı."
        });

      }


      /* =========================
         EMAIL CHECK
      ========================= */

      const {
        data: emailUser,
        error: emailError
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
          "EMAIL CHECK ERROR:",
          emailError
        );

        return res.status(500).json({
          success: false,
          message:
            "E-posta kontrolü başarısız."
        });

      }


      if (emailUser) {

        return res.status(409).json({
          success: false,
          message:
            "Bu e-posta zaten kayıtlı."
        });

      }


      /* =========================
         PHONE CHECK
      ========================= */

      const {
        data: phoneUser,
        error: phoneError
      } =
        await supabase
          .from("users")
          .select("id")
          .eq(
            "phone",
            cleanPhone
          )
          .maybeSingle();


      if (phoneError) {

        console.error(
          "PHONE CHECK ERROR:",
          phoneError
        );

        return res.status(500).json({
          success: false,
          message:
            "Telefon numarası kontrolü başarısız."
        });

      }


      if (phoneUser) {

        return res.status(409).json({
          success: false,
          message:
            "Bu telefon numarası zaten kayıtlı."
        });

      }


      /* =========================
         PASSWORD HASH
      ========================= */

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );


      /* =========================
         VERIFICATION CODE
      ========================= */

      const verificationCode =
        crypto
          .randomInt(
            100000,
            1000000
          )
          .toString();


      const verificationCodeHash =
        await bcrypt.hash(
          verificationCode,
          10
        );


      const verificationExpiresAt =
        new Date(
          Date.now() +
          10 * 60 * 1000
        ).toISOString();


      const createdAt =
        new Date().toISOString();


      /* =========================
         CREATE USER
      ========================= */

      const {
        data: newUser,
        error: insertError
      } =
        await supabase
          .from("users")
          .insert({

            username:
              cleanUsername,

            email:
              cleanEmail,

            phone:
              cleanPhone,

            password_hash:
              passwordHash,

            created_at:
              createdAt,

            email_verified:
              0,

            verification_code_hash:
              verificationCodeHash,

            verification_expires_at:
              verificationExpiresAt

          })
          .select(
            "id, username, email, phone"
          )
          .single();


      /* =========================
         INSERT ERROR
      ========================= */

      if (insertError) {

        console.error(
          "SUPABASE REGISTER ERROR:",
          insertError
        );


        /*
         * Supabase unique index tarafından
         * aynı telefon numarası engellenirse
         * 409 döndür.
         */

        if (
          insertError.code === "23505"
        ) {

          const errorText =
            (
              String(
                insertError.message || ""
              ) +
              " " +
              String(
                insertError.details || ""
              ) +
              " " +
              String(
                insertError.hint || ""
              )
            ).toLowerCase();


          if (
            errorText.includes(
              "users_phone_unique"
            ) ||
            errorText.includes(
              "phone"
            )
          ) {

            return res.status(409).json({
              success: false,
              message:
                "Bu telefon numarası zaten kayıtlı."
            });

          }

        }


        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı oluşturulamadı."
        });

      }


      /* =========================
         SEND VERIFICATION EMAIL
      ========================= */

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

        return res.status(500).json({
          success: false,
          message:
            "Hesap oluşturuldu ancak doğrulama e-postası gönderilemedi. Lütfen yeni doğrulama kodu iste."
        });

      }


      /* =========================
         SUCCESS
      ========================= */

      return res.status(201).json({

        success: true,

        message:
          "Hesap oluşturuldu. Doğrulama kodu e-posta adresine gönderildi.",

        userId:
          newUser.id

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

  }
);


/* =========================
   VERIFY EMAIL
========================= */

app.post(
  "/api/auth/verify-email",
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const code =
        String(
          req.body.code || ""
        ).trim();

      if (!email || !code) {

        return res.status(400).json({
          success: false,
          message:
            "E-posta ve doğrulama kodu gerekli."
        });

      }

      const {
        data: user,
        error
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            email
          )
          .maybeSingle();

      if (error) {

        console.error(
          "VERIFY USER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });

      }

      if (
        Number(user.email_verified) === 1
      ) {

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
        new Date(
          user.verification_expires_at
        ).getTime() < Date.now()
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

      const {
        error: updateError
      } =
        await supabase
          .from("users")
          .update({

            email_verified:
              1,

            verification_code_hash:
              null,

            verification_expires_at:
              null

          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {

        console.error(
          "VERIFY UPDATE ERROR:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "E-posta doğrulaması kaydedilemedi."
        });

      }

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
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      if (!email) {

        return res.status(400).json({
          success: false,
          message:
            "E-posta gerekli."
        });

      }

      const {
        data: user,
        error
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            email
          )
          .maybeSingle();

      if (error) {

        console.error(
          "RESEND USER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });

      }

      if (
        Number(user.email_verified) === 1
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Bu e-posta adresi zaten doğrulanmış."
        });

      }

      const verificationCode =
        crypto
          .randomInt(
            100000,
            1000000
          )
          .toString();

      const verificationCodeHash =
        await bcrypt.hash(
          verificationCode,
          10
        );

      const verificationExpiresAt =
        new Date(
          Date.now() +
          10 * 60 * 1000
        ).toISOString();

      const {
        error: updateError
      } =
        await supabase
          .from("users")
          .update({

            verification_code_hash:
              verificationCodeHash,

            verification_expires_at:
              verificationExpiresAt

          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {

        console.error(
          "RESEND UPDATE ERROR:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Doğrulama kodu oluşturulamadı."
        });

      }

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
        String(
          login ||
          username ||
          ""
        ).trim();

      if (
        !loginValue ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Kullanıcı adı/e-posta ve şifre gerekli."
        });

      }

      const {
        data: usernameUser,
        error: usernameError
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "username",
            loginValue
          )
          .maybeSingle();

      if (usernameError) {

        console.error(
          "LOGIN USERNAME ERROR:",
          usernameError
        );

        return res.status(500).json({
          success: false,
          message:
            "Giriş sırasında hata oluştu."
        });

      }

      let user =
        usernameUser;

      if (!user) {

        const {
          data: emailUser,
          error: emailError
        } =
          await supabase
            .from("users")
            .select("*")
            .eq(
              "email",
              loginValue.toLowerCase()
            )
            .maybeSingle();

        if (emailError) {

          console.error(
            "LOGIN EMAIL ERROR:",
            emailError
          );

          return res.status(500).json({
            success: false,
            message:
              "Giriş sırasında hata oluştu."
          });

        }

        user =
          emailUser;

      }

      if (!user) {

        return res.status(401).json({
          success: false,
          message:
            "Kullanıcı adı veya şifre yanlış."
        });

      }

      if (
        Number(user.email_verified) !== 1
      ) {

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

        id:
          user.id,

        username:
          user.username,

        email:
          user.email,

        role:
          "user"

      };

      const token =
        createToken(
          safeUser
        );

      return res.json({

        success: true,

        message:
          "Giriş başarılı.",

        user:
          safeUser,

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

  }
);


/* =========================
   FORGOT PASSWORD
========================= */

app.post(
  "/api/auth/forgot-password",
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      if (!email) {

        return res.status(400).json({
          success: false,
          message:
            "E-posta gerekli."
        });

      }

      const {
        data: user,
        error
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "email",
            email
          )
          .maybeSingle();

      if (error) {

        console.error(
          "FORGOT USER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "Bu e-posta ile kayıtlı kullanıcı bulunamadı."
        });

      }

      const code =
        crypto
          .randomInt(
            100000,
            1000000
          )
          .toString();

      const codeHash =
        await bcrypt.hash(
          code,
          10
        );

      const expiresAt =
        new Date(
          Date.now() +
          10 * 60 * 1000
        ).toISOString();

      const {
        error: updateError
      } =
        await supabase
          .from("users")
          .update({

            verification_code_hash:
              codeHash,

            verification_expires_at:
              expiresAt

          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {

        console.error(
          "FORGOT UPDATE ERROR:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre sıfırlama kodu oluşturulamadı."
        });

      }

      await sendPasswordResetEmail(
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
        String(
          email || ""
        )
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

      if (
        password !==
        passwordConfirm
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Şifreler aynı değil."
        });

      }

      if (
        password.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Şifre en az 6 karakter olmalı."
        });

      }

      const {
        data: user,
        error
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
          "RESET USER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

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
        new Date(
          user.verification_expires_at
        ).getTime() < Date.now()
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
        await bcrypt.hash(
          password,
          12
        );

      const {
        error: updateError
      } =
        await supabase
          .from("users")
          .update({

            password_hash:
              passwordHash,

            verification_code_hash:
              null,

            verification_expires_at:
              null

          })
          .eq(
            "id",
            user.id
          );

      if (updateError) {

        console.error(
          "RESET UPDATE ERROR:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre değiştirilemedi."
        });

      }

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

      if (
        req.user.role === "admin"
      ) {

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

      if (
        newPassword !==
        newPasswordConfirm
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Yeni şifreler aynı değil."
        });

      }

      if (
        newPassword.length < 6
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Yeni şifre en az 6 karakter olmalı."
        });

      }

      const {
        data: user,
        error
      } =
        await supabase
          .from("users")
          .select("*")
          .eq(
            "id",
            req.user.id
          )
          .maybeSingle();

      if (error) {

        console.error(
          "CHANGE PASSWORD USER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

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
        await bcrypt.hash(
          newPassword,
          12
        );

      const {
        error: updateError
      } =
        await supabase
          .from("users")
          .update({

            password_hash:
              newHash

          })
          .eq(
            "id",
            req.user.id
          );

      if (updateError) {

        console.error(
          "CHANGE PASSWORD UPDATE ERROR:",
          updateError
        );

        return res.status(500).json({
          success: false,
          message:
            "Şifre değiştirilemedi."
        });

      }

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
  async (req, res) => {

    try {

      if (
        req.user.role === "admin"
      ) {

        return res.json({
          success: true,
          user:
            req.user
        });

      }

      const {
        data: user,
        error
      } =
        await supabase
          .from("users")
          .select(
            "id, username, email, phone, created_at, email_verified"
          )
          .eq(
            "id",
            req.user.id
          )
          .maybeSingle();

      if (error) {

        console.error(
          "ME ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Kullanıcı bilgileri alınamadı."
        });

      }

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
          role:
            "user"
        }

      });

    } catch (error) {

      console.error(
        "ME ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcı bilgileri alınamadı."
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

      if (
        !username ||
        !password
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Admin kullanıcı adı ve şifre gerekli."
        });

      }

      if (
        username !==
        ADMIN_USERNAME ||
        password !==
        ADMIN_PASSWORD
      ) {

        return res.status(401).json({
          success: false,
          message:
            "Admin kullanıcı adı veya şifre yanlış."
        });

      }

      const admin = {

        username:
          ADMIN_USERNAME,

        role:
          "admin"

      };

      const token =
        createToken(
          admin
        );

      return res.json({

        success: true,

        message:
          "Admin girişi başarılı.",

        user:
          admin,

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
  async (req, res) => {

    try {

      const {
        count: userCount,
        error: userError
      } =
        await supabase
          .from("users")
          .select(
            "id",
            {
              count: "exact",
              head: true
            }
          );

      if (userError) {
        throw userError;
      }

      const {
        count: orderCount,
        error: orderError
      } =
        await supabase
          .from("orders")
          .select(
            "id",
            {
              count: "exact",
              head: true
            }
          );

      if (orderError) {
        throw orderError;
      }

      const {
        count: newOrderCount,
        error: newOrderError
      } =
        await supabase
          .from("orders")
          .select(
            "id",
            {
              count: "exact",
              head: true
            }
          )
          .eq(
            "status",
            "Yeni"
          );

      if (newOrderError) {
        throw newOrderError;
      }

      const {
        data: totals,
        error: totalError
      } =
        await supabase
          .from("orders")
          .select(
            "total, status"
          );

      if (totalError) {
        throw totalError;
      }

      let totalAmount = 0;

      for (
        const order of totals || []
      ) {

        if (
          order.status !==
          "İptal"
        ) {

          totalAmount +=
            Number(
              order.total
            ) || 0;

        }

      }

      return res.json({

        success: true,

        stats: {

          userCount:
            userCount || 0,

          orderCount:
            orderCount || 0,

          newOrderCount:
            newOrderCount || 0,

          totalAmount:
            totalAmount

        }

      });

    } catch (error) {

      console.error(
        "ADMIN STATS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "İstatistikler alınamadı."
      });

    }

  }
);


/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  authenticateAdmin,
  async (req, res) => {

    try {

      const {
        data: users,
        error
      } =
        await supabase
          .from("users")
          .select(
            "id, username, email, phone, created_at, email_verified"
          )
          .order(
            "id",
            {
              ascending: false
            }
          );

      if (error) {
        throw error;
      }

      return res.json({

        success: true,

        users:
          users || []

      });

    } catch (error) {

      console.error(
        "ADMIN USERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcılar alınamadı."
      });

    }

  }
);


/* =========================
   ADMIN USER DELETE
========================= */

app.delete(
  "/api/admin/users/:id",
  authenticateAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz kullanıcı ID."
        });

      }

      const {
        data: user,
        error: findError
      } =
        await supabase
          .from("users")
          .select("id")
          .eq(
            "id",
            id
          )
          .maybeSingle();

      if (findError) {
        throw findError;
      }

      if (!user) {

        return res.status(404).json({
          success: false,
          message:
            "Kullanıcı bulunamadı."
        });

      }

      const {
        error: deleteError
      } =
        await supabase
          .from("users")
          .delete()
          .eq(
            "id",
            id
          );

      if (deleteError) {
        throw deleteError;
      }

      return res.json({
        success: true,
        message:
          "Kullanıcı silindi."
      });

    } catch (error) {

      console.error(
        "ADMIN USER DELETE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Kullanıcı silinemedi."
      });

    }

  }
);


/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  authenticateAdmin,
  async (req, res) => {

    try {

      const {
        data: orders,
        error
      } =
        await supabase
          .from("orders")
          .select("*")
          .order(
            "id",
            {
              ascending: false
            }
          );

      if (error) {
        throw error;
      }

      return res.json({

        success: true,

        orders:
          orders || []

      });

    } catch (error) {

      console.error(
        "ADMIN ORDERS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Siparişler alınamadı."
      });

    }

  }
);


/* =========================
   ADMIN ORDER STATUS
========================= */

app.patch(
  "/api/admin/orders/:id/status",
  authenticateAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

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

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz sipariş ID."
        });

      }

      if (
        !allowedStatuses.includes(
          status
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz sipariş durumu."
        });

      }

      const {
        data: existingOrder,
        error: findError
      } =
        await supabase
          .from("orders")
          .select("id")
          .eq(
            "id",
            id
          )
          .maybeSingle();

      if (findError) {
        throw findError;
      }

      if (!existingOrder) {

        return res.status(404).json({
          success: false,
          message:
            "Sipariş bulunamadı."
        });

      }

      const {
        error: updateError
      } =
        await supabase
          .from("orders")
          .update({
            status:
              status
          })
          .eq(
            "id",
            id
          );

      if (updateError) {
        throw updateError;
      }

      return res.json({
        success: true,
        message:
          "Sipariş durumu güncellendi."
      });

    } catch (error) {

      console.error(
        "ADMIN ORDER STATUS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Sipariş durumu güncellenemedi."
      });

    }

  }
);


/* =========================
   ADMIN ORDER DELETE
========================= */

app.delete(
  "/api/admin/orders/:id",
  authenticateAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Geçersiz sipariş ID."
        });

      }

      const {
        data: order,
        error: findError
      } =
        await supabase
          .from("orders")
          .select("id")
          .eq(
            "id",
            id
          )
          .maybeSingle();

      if (findError) {
        throw findError;
      }

      if (!order) {

        return res.status(404).json({
          success: false,
          message:
            "Sipariş bulunamadı."
        });

      }

      const {
        error: deleteError
      } =
        await supabase
          .from("orders")
          .delete()
          .eq(
            "id",
            id
          );

      if (deleteError) {
        throw deleteError;
      }

      return res.json({
        success: true,
        message:
          "Sipariş silindi."
      });

    } catch (error) {

      console.error(
        "ADMIN ORDER DELETE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Sipariş silinemedi."
      });

    }

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
        JSON.stringify(
          items
        );

      const createdAt =
        new Date().toISOString();

      const {
        data: newOrder,
        error
      } =
        await supabase
          .from("orders")
          .insert({

            user_id:
              req.user.id,

            customer_name:
              customerName,

            customer_phone:
              customerPhone,

            customer_address:
              customerAddress,

            customer_note:
              customerNote || "",

            items_json:
              itemsJson,

            total:
              Number(total) || 0,

            status:
              "Yeni",

            created_at:
              createdAt

          })
          .select("id")
          .single();

      if (error) {

        console.error(
          "SUPABASE ORDER ERROR:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Sipariş oluşturulamadı."
        });

      }

      return res.status(201).json({

        success: true,

        message:
          "Sipariş başarıyla oluşturuldu.",

        orderId:
          newOrder.id

      });

    } catch (error) {

      console.error(
        "ORDER ERROR:",
        error
      );

      return res.status(500).json({
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

async function sendOrderEmail(
  order
) {

  if (!BREVO_API_KEY) {
    return;
  }

  if (!BREVO_SENDER_EMAIL) {
    return;
  }

  const itemsText =
    Array.isArray(
      order.items
    )
      ? order.items
          .map(
            item =>
              `${item.name || "Ürün"} x${item.quantity || 1}`
          )
          .join("\n")
      : "Ürün bilgisi yok";

  const emailText =
`
Yeni VELORA siparişi

Sipariş No:
${order.orderId}

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

  return sendBrevoEmail({

    to:
      BREVO_SENDER_EMAIL,

    subject:
      `VELORA Yeni Sipariş #${order.orderId}`,

    textContent:
      emailText

  });
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

    console.log(
      "Supabase bağlantısı hazır."
    );

  }
);
