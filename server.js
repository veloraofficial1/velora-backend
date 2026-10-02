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

// ======================================================
// ENV
// ======================================================

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!JWT_SECRET) console.error("UYARI: JWT_SECRET environment variable bulunamadı.");
if (!SUPABASE_URL) console.error("UYARI: SUPABASE_URL environment variable bulunamadı.");
if (!SUPABASE_SERVICE_ROLE_KEY) console.error("UYARI: SUPABASE_SERVICE_ROLE_KEY environment variable bulunamadı.");

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
    { expiresIn: "7d" }
  );
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

// ======================================================
// KULLANICI AUTH MIDDLEWARE
// ======================================================

function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Giriş yapmanız gerekiyor.",
      });
    }

    const token = authHeader.startsWith("Bearer ")
        ? authHeader.substring(7)
        : authHeader;

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Auth middleware hatası:", error.message);
    return res.status(401).json({
      success: false,
      message: "Geçersiz veya süresi dolmuş oturum.",
    });
  }
}

// ======================================================
// BREVO EMAIL
// ======================================================

async function sendEmail({ to, subject, html }) {
  const apiKey = process.env.BREVO_API_KEY;
  const senderEmail = process.env.BREVO_SENDER_EMAIL;
  const senderName = process.env.BREVO_SENDER_NAME || "VELORA";

  if (!apiKey || !senderEmail) {
    console.log("Brevo ayarları bulunamadı. E-posta gönderilemedi.");
    return false;
  }

  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "api-key": apiKey,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        sender: { name: senderName, email: senderEmail },
        to: [{ email: normalizeEmail(to) }],
        subject,
        htmlContent: html,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error("Brevo email hatası:", text);
      return false;
    }
    return true;
  } catch (error) {
    console.error("Email gönderme hatası:", error);
    return false;
  }
}

// ======================================================
// ANA SAYFA & HEALTH
// ======================================================

app.get("/", (req, res) => {
  res.json({ success: true, message: "VELORA backend çalışıyor." });
});

app.get("/api/health", (req, res) => {
  res.json({ success: true, message: "VELORA API çalışıyor." });
});

// ======================================================
// REGISTER (Ad ve Soyad Destekli)
// ======================================================

app.post("/api/auth/register", async (req, res) => {
  try {
    const { firstName, lastName, username, email, password, passwordConfirm } = req.body;
    const cleanFirstName = String(firstName || "").trim();
    const cleanLastName = String(lastName || "").trim();
    const cleanUsername = normalizeUsername(username);
    const cleanEmail = normalizeEmail(email);

    if (!cleanFirstName || !cleanLastName || !cleanUsername || !cleanEmail || !password || !passwordConfirm) {
      return res.status(400).json({ success: false, message: "Lütfen tüm alanları doldurun." });
    }
    if (cleanUsername.length < 3) {
      return res.status(400).json({ success: false, message: "Kullanıcı adı en az 3 karakter olmalıdır." });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: "Şifre en az 6 karakter olmalıdır." });
    }
    if (password !== passwordConfirm) {
      return res.status(400).json({ success: false, message: "Şifreler eşleşmiyor." });
    }

    const { data: usernameUser, error: usernameError } = await supabase
      .from("users")
      .select("id")
      .eq("username", cleanUsername)
      .maybeSingle();

    if (usernameError) return res.status(500).json({ success: false, message: "Kullanıcı kontrolü sırasında hata oluştu." });
    if (usernameUser) return res.status(400).json({ success: false, message: "Bu kullanıcı adı zaten kullanılıyor." });

    const { data: emailUser, error: emailError } = await supabase
      .from("users")
      .select("id")
      .eq("email", cleanEmail)
      .maybeSingle();

    if (emailError) return res.status(500).json({ success: false, message: "E-posta kontrolü sırasında hata oluştu." });
    if (emailUser) return res.status(400).json({ success: false, message: "Bu e-posta adresi zaten kullanılıyor." });

    const passwordHash = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();
    const verificationExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    const { data: user, error: insertError } = await supabase
      .from("users")
      .insert({
        first_name: cleanFirstName,
        last_name: cleanLastName,
        username: cleanUsername,
        email: cleanEmail,
        password_hash: passwordHash,
        email_verified: false,
        verification_code: verificationCode,
        verification_expires_at: verificationExpiresAt,
      })
      .select()
      .single();

    if (insertError) {
      console.error("Kullanıcı oluşturma Supabase hatası:", insertError);
      return res.status(500).json({ success: false, message: "Kullanıcı oluşturulamadı." });
    }

    await sendEmail({
      to: cleanEmail,
      subject: "VELORA - E-posta Doğrulama",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
          <h1 style="color:#9b7445;">VELORA</h1>
          <h2>E-posta Doğrulama</h2>
          <p>Merhaba ${cleanFirstName},</p>
          <p>VELORA hesabınızı doğrulamak için aşağıdaki kodu kullanın:</p>
          <div style="font-size:32px; font-weight:bold; letter-spacing:8px; padding:20px; background:#f7f1e7; text-align:center; color:#4c3b2b;">
            ${verificationCode}
          </div>
          <p>Bu kod 15 dakika boyunca geçerlidir.</p>
        </div>
      `,
    });

    return res.status(201).json({
      success: true,
      message: "Hesabınız oluşturuldu. E-posta adresinize gönderilen doğrulama kodunu girin.",
      user: { id: user.id, username: user.username, email: user.email, first_name: user.first_name, last_name: user.last_name },
    });

  } catch (error) {
    console.error("Register genel hata:", error);
    return res.status(500).json({ success: false, message: "Kullanıcı oluşturulamadı." });
  }
});

// ======================================================
// EMAIL VERIFY
// ======================================================

app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { email, code } = req.body;
    const cleanEmail = normalizeEmail(email);
    const cleanCode = String(code || "").trim();

    if (!cleanEmail || !cleanCode) {
      return res.status(400).json({ success: false, message: "E-posta ve doğrulama kodu gereklidir." });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", cleanEmail)
      .maybeSingle();

    if (error) return res.status(500).json({ success: false, message: "Doğrulama sırasında hata oluştu." });
    if (!user) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });
    if (user.email_verified) return res.json({ success: true, message: "E-posta adresiniz zaten doğrulanmış." });
    if (user.verification_code !== cleanCode) return res.status(400).json({ success: false, message: "Doğrulama kodu yanlış." });
    if (user.verification_expires_at && new Date(user.verification_expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: "Doğrulama kodunun süresi dolmuş." });
    }

    const { error: updateError } = await supabase
      .from("users")
      .update({ email_verified: true, verification_code: null, verification_expires_at: null })
      .eq("id", user.id);

    if (updateError) return res.status(500).json({ success: false, message: "E-posta doğrulanamadı." });

    return res.json({ success: true, message: "E-posta adresiniz başarıyla doğrulandı." });

  } catch (error) {
    console.error("Verify genel hata:", error);
    return res.status(500).json({ success: false, message: "Doğrulama sırasında hata oluştu." });
  }
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const cleanEmail = normalizeEmail(email);

    if (!cleanEmail || !password) {
      return res.status(400).json({ success: false, message: "E-posta ve şifre gereklidir." });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", cleanEmail)
      .maybeSingle();

    if (error) return res.status(500).json({ success: false, message: "Giriş sırasında hata oluştu." });
    if (!user) return res.status(401).json({ success: false, message: "E-posta veya şifre hatalı." });

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ success: false, message: "E-posta veya şifre hatalı." });
    if (user.email_verified === false) {
      return res.status(403).json({ success: false, message: "Lütfen önce e-posta adresinizi doğrulayın.", emailVerified: false });
    }

    const token = createToken(user);
    return res.json({
      success: true,
      message: "Giriş başarılı.",
      token,
      user: { id: user.id, username: user.username, email: user.email, first_name: user.first_name, last_name: user.last_name },
    });

  } catch (error) {
    console.error("Login genel hata:", error);
    return res.status(500).json({ success: false, message: "Giriş yapılamadı." });
  }
});

// ======================================================
// FORGOT & RESET PASSWORD
// ======================================================

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail) return res.status(400).json({ success: false, message: "E-posta adresi gereklidir." });

    const { data: user, error } = await supabase.from("users").select("*").eq("email", cleanEmail).maybeSingle();
    if (error) return res.status(500).json({ success: false, message: "İşlem sırasında hata oluştu." });
    if (!user) return res.json({ success: true, message: "Eğer bu e-posta kayıtlıysa şifre sıfırlama kodu gönderildi." });

    const resetCode = generateVerificationCode();
    const resetExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await supabase
      .from("users")
      .update({ verification_code: resetCode, verification_expires_at: resetExpiresAt })
      .eq("id", user.id);

    await sendEmail({
      to: cleanEmail,
      subject: "VELORA - Şifre Sıfırlama",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;">
          <h1 style="color:#9b7445;">VELORA</h1>
          <h2>Şifre Sıfırlama</h2>
          <p>Merhaba ${user.first_name || user.username},</p>
          <p>Şifrenizi sıfırlamak için aşağıdaki kodu kullanın:</p>
          <div style="font-size:32px; font-weight:bold; letter-spacing:8px; padding:20px; background:#f7f1e7; text-align:center; color:#4c3b2b;">
            ${resetCode}
          </div>
          <p>Bu kod 15 dakika boyunca geçerlidir.</p>
        </div>
      `,
    });

    return res.json({ success: true, message: "Eğer bu e-posta kayıtlıysa şifre sıfırlama kodu gönderildi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Şifre sıfırlama işlemi başarısız." });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword, passwordConfirm } = req.body;
    const cleanEmail = normalizeEmail(email);
    const cleanCode = String(code || "").trim();

    if (!cleanEmail || !cleanCode || !newPassword || !passwordConfirm) {
      return res.status(400).json({ success: false, message: "Lütfen tüm alanları doldurun." });
    }
    if (newPassword.length < 6) return res.status(400).json({ success: false, message: "Şifre en az 6 karakter olmalıdır." });
    if (newPassword !== passwordConfirm) return res.status(400).json({ success: false, message: "Şifreler eşleşmiyor." });

    const { data: user, error } = await supabase.from("users").select("*").eq("email", cleanEmail).maybeSingle();
    if (error || !user) return res.status(400).json({ success: false, message: "Geçersiz bilgiler." });
    if (user.verification_code !== cleanCode) return res.status(400).json({ success: false, message: "Kod yanlış." });
    if (user.verification_expires_at && new Date(user.verification_expires_at) < new Date()) {
      return res.status(400).json({ success: false, message: "Kodun süresi dolmuş." });
    }

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await supabase
      .from("users")
      .update({ password_hash: passwordHash, verification_code: null, verification_expires_at: null })
      .eq("id", user.id);

    return res.json({ success: true, message: "Şifreniz başarıyla değiştirildi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Şifre sıfırlama başarısız." });
  }
});

app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword, passwordConfirm } = req.body;
    if (!currentPassword || !newPassword || !passwordConfirm) return res.status(400).json({ success: false, message: "Lütfen tüm alanları doldurun." });
    if (newPassword.length < 6) return res.status(400).json({ success: false, message: "Yeni şifre en az 6 karakter olmalıdır." });
    if (newPassword !== passwordConfirm) return res.status(400).json({ success: false, message: "Yeni şifreler eşleşmiyor." });

    const { data: user, error } = await supabase.from("users").select("*").eq("id", req.user.id).maybeSingle();
    if (error || !user) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });

    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) return res.status(400).json({ success: false, message: "Mevcut şifreniz yanlış." });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await supabase.from("users").update({ password_hash: passwordHash }).eq("id", user.id);

    return res.json({ success: true, message: "Şifreniz başarıyla değiştirildi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Şifreniz değiştirilemedi." });
  }
});

// ======================================================
// ME (Ad ve Soyad Eklendi)
// ======================================================

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, username, email, email_verified, first_name, last_name")
      .eq("id", req.user.id)
      .maybeSingle();

    if (error || !user) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });
    return res.json({ success: true, user });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Kullanıcı bilgileri alınamadı." });
  }
});

// ======================================================
// UPDATE PROFILE (YENİ EKLENDİ - 404 HATASINI ÇÖZER)
// ======================================================

app.post("/api/auth/update-profile", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, firstName, lastName, username, email } = req.body;
    
    if (!currentPassword) {
      return res.status(400).json({ success: false, message: "Değişiklikleri onaylamak için mevcut şifrenizi girmelisiniz." });
    }

    const { data: user, error } = await supabase.from("users").select("*").eq("id", req.user.id).maybeSingle();
    if (error || !user) return res.status(404).json({ success: false, message: "Kullanıcı bulunamadı." });

    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) return res.status(400).json({ success: false, message: "Mevcut şifreniz yanlış." });

    const updateData = {};
    if (firstName !== undefined) updateData.first_name = String(firstName).trim();
    if (lastName !== undefined) updateData.last_name = String(lastName).trim();
    if (username !== undefined) updateData.username = normalizeUsername(username);
    if (email !== undefined) updateData.email = normalizeEmail(email);

    const { data: updatedUser, error: updateError } = await supabase
      .from("users")
      .update(updateData)
      .eq("id", user.id)
      .select("id, username, email, first_name, last_name")
      .single();

    if (updateError) return res.status(500).json({ success: false, message: "Profil güncellenemedi." });

    return res.json({ success: true, message: "Bilgileriniz başarıyla güncellendi.", user: updatedUser });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Güncelleme sırasında bir hata oluştu." });
  }
});

// ======================================================
// FAVORITES
// ======================================================

app.get("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from("favorites").select("*").eq("user_id", req.user.id);
    if (error) return res.status(500).json({ success: false, message: "Favoriler alınamadı." });
    return res.json({ success: true, favorites: data || [] });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Favoriler alınamadı." });
  }
});

app.post("/api/favorites", authMiddleware, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) return res.status(400).json({ success: false, message: "Ürün ID gereklidir." });

    const { data, error } = await supabase
      .from("favorites")
      .upsert({ user_id: req.user.id, product_id: productId }, { onConflict: "user_id,product_id" })
      .select()
      .single();

    if (error) return res.status(500).json({ success: false, message: "Favorilere eklenemedi." });
    return res.json({ success: true, favorite: data });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Favorilere eklenemedi." });
  }
});

app.delete("/api/favorites/:productId", authMiddleware, async (req, res) => {
  try {
    const { productId } = req.params;
    const { error } = await supabase.from("favorites").delete().eq("user_id", req.user.id).eq("product_id", productId);
    if (error) return res.status(500).json({ success: false, message: "Favorilerden kaldırılamadı." });
    return res.json({ success: true, message: "Favorilerden kaldırıldı." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Favorilerden kaldırılamadı." });
  }
});

// ======================================================
// ORDERS & STATUS
// ======================================================

const VALID_ORDER_STATUSES = ["pending", "preparing", "shipped", "out_for_delivery", "delivered", "cancelled"];
const ORDER_STATUS_LABELS = {
  pending: "Sipariş Alındı",
  preparing: "Hazırlanıyor",
  shipped: "Kargoya Verildi",
  out_for_delivery: "Dağıtımda",
  delivered: "Teslim Edildi",
  cancelled: "İptal Edildi",
};

const LEGACY_ORDER_STATUS_MAP = {
  Yeni: "pending", "Sipariş Alındı": "pending", pending: "pending",
  "Hazırlanıyor": "preparing", preparing: "preparing",
  Kargoda: "shipped", "Kargoya Verildi": "shipped", shipped: "shipped",
  Dağıtımda: "out_for_delivery", out_for_delivery: "out_for_delivery",
  "Teslim Edildi": "delivered", delivered: "delivered",
  İptal: "cancelled", "İptal Edildi": "cancelled", cancelled: "cancelled",
};

function normalizeOrderStatus(status) {
  const value = String(status || "").trim();
  return LEGACY_ORDER_STATUS_MAP[value] || "pending";
}

app.get("/api/orders/my", authMiddleware, async (req, res) => {
  try {
    const userId = req.user?.id;
    const userEmail = normalizeEmail(req.user?.email);

    if (!userId) return res.status(401).json({ success: false, message: "Kullanıcı kimliği bulunamadı." });

    const { data: userIdOrders } = await supabase.from("orders").select("*").eq("user_id", userId);
    let emailOrders = [];
    if (userEmail) {
      const { data } = await supabase.from("orders").select("*").eq("customer_email", userEmail);
      if (data) emailOrders = data;
    }

    const combinedOrders = [...(userIdOrders || []), ...emailOrders];
    const uniqueOrders = [];
    const seenOrderIds = new Set();

    for (const order of combinedOrders) {
      const orderId = String(order.id ?? "");
      if (orderId && seenOrderIds.has(orderId)) continue;
      if (orderId) seenOrderIds.add(orderId);
      uniqueOrders.push(order);
    }

    uniqueOrders.sort((a, b) => {
      const dateA = a.created_at ? new Date(a.created_at).getTime() : 0;
      const dateB = b.created_at ? new Date(b.created_at).getTime() : 0;
      return dateB - dateA;
    });

    const orders = uniqueOrders.map((order) => {
      const status = normalizeOrderStatus(order.status);
      return { ...order, status, statusLabel: ORDER_STATUS_LABELS[status] || "Sipariş Alındı" };
    });

    return res.json({ success: true, orders });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Siparişler alınamadı." });
  }
});

app.post("/api/orders", authMiddleware, async (req, res) => {
  try {
    const { customerName, customerEmail, customerPhone, address, items, total } = req.body;
    if (!customerName || !customerEmail || !customerPhone || !address || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, message: "Sipariş bilgileri eksik." });
    }

    const userId = req.user?.id;
    const userEmail = normalizeEmail(req.user?.email);
    if (!userId) return res.status(401).json({ success: false, message: "Kullanıcı kimliği bulunamadı." });

    const cleanCustomerEmail = normalizeEmail(customerEmail || userEmail);

    const { data: order, error } = await supabase
      .from("orders")
      .insert({
        user_id: userId,
        customer_name: String(customerName).trim(),
        customer_email: cleanCustomerEmail,
        customer_phone: String(customerPhone).trim(),
        address: String(address).trim(),
        items: items,
        total: Number(total) || 0,
        status: "pending",
      })
      .select()
      .single();

    if (error) return res.status(500).json({ success: false, message: "Sipariş oluşturulamadı." });

    return res.status(201).json({ success: true, message: "Siparişiniz başarıyla oluşturuldu.", order });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Sipariş oluşturulurken bir hata oluştu." });
  }
});

// ======================================================
// ADMIN GENEL & REVIEWS
// ======================================================

app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ success: false, message: "Admin kullanıcı adı veya şifre hatalı." });
    }
    const token = jwt.sign({ admin: true, username }, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ success: true, message: "Admin girişi başarılı.", token });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Admin girişi yapılamadı." });
  }
});

function adminMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: "Admin girişi gerekiyor." });
    const token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.admin) return res.status(403).json({ success: false, message: "Admin yetkisi gerekiyor." });
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: "Geçersiz admin oturumu." });
  }
}

app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  try {
    const { count: usersCount } = await supabase.from("users").select("*", { count: "exact", head: true });
    const { count: ordersCount } = await supabase.from("orders").select("*", { count: "exact", head: true });
    return res.json({ success: true, stats: { users: usersCount || 0, orders: ordersCount || 0 } });
  } catch (error) {
    return res.status(500).json({ success: false, message: "İstatistikler alınamadı." });
  }
});

app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from("users").select("id, username, email, email_verified, first_name, last_name").order("id", { ascending: false });
    if (error) return res.status(500).json({ success: false, message: "Kullanıcılar alınamadı." });
    return res.json({ success: true, users: data || [] });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Kullanıcılar alınamadı." });
  }
});

app.delete("/api/admin/users/:id", adminMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from("users").delete().eq("id", req.params.id);
    if (error) return res.status(500).json({ success: false, message: "Kullanıcı silinemedi." });
    return res.json({ success: true, message: "Kullanıcı silindi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Kullanıcı silinemedi." });
  }
});

app.get("/api/admin/orders", adminMiddleware, async (req, res) => {
  try {
    const { data, error } = await supabase.from("orders").select("*").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ success: false, message: "Siparişler alınamadı." });
    const orders = (data || []).map((order) => {
      const status = normalizeOrderStatus(order.status);
      return { ...order, status, statusLabel: ORDER_STATUS_LABELS[status] || "Sipariş Alındı" };
    });
    return res.json({ success: true, orders });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Siparişler alınamadı." });
  }
});

async function updateAdminOrderStatus(req, res) {
  try {
    const { id } = req.params;
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ success: false, message: "Durum gereklidir." });
    const normalizedStatus = normalizeOrderStatus(status);
    if (!VALID_ORDER_STATUSES.includes(normalizedStatus)) return res.status(400).json({ success: false, message: "Geçersiz sipariş durumu." });

    const { data, error } = await supabase.from("orders").update({ status: normalizedStatus }).eq("id", id).select().single();
    if (error) return res.status(500).json({ success: false, message: "Sipariş durumu güncellenemedi." });

    return res.json({ success: true, message: "Sipariş durumu güncellendi.", order: { ...data, status: normalizeOrderStatus(data.status), statusLabel: ORDER_STATUS_LABELS[normalizedStatus] } });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Sipariş durumu güncellenemedi." });
  }
}

app.put("/api/admin/orders/:id/status", adminMiddleware, updateAdminOrderStatus);
app.patch("/api/admin/orders/:id/status", adminMiddleware, updateAdminOrderStatus);

app.delete("/api/admin/orders/:id", adminMiddleware, async (req, res) => {
  try {
    const { error } = await supabase.from("orders").delete().eq("id", req.params.id);
    if (error) return res.status(500).json({ success: false, message: "Sipariş silinemedi." });
    return res.json({ success: true, message: "Sipariş silindi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Sipariş silinemedi." });
  }
});

app.get("/api/reviews/:productId", async (req, res) => {
  try {
    const productId = Number(req.params.productId);
    if (!Number.isFinite(productId)) return res.status(400).json({ success: false, message: "Geçersiz ürün ID." });

    const { data: reviews, error } = await supabase
      .from("reviews")
      .select("id, product_id, user_id, rating, comment, created_at")
      .eq("product_id", productId)
      .order("created_at", { ascending: false });

    if (error) return res.status(500).json({ success: false, message: "Değerlendirmeler alınamadı." });

    const rows = Array.isArray(reviews) ? reviews : [];
    const userIds = [...new Set(rows.map(r => r.user_id).filter(Boolean))];

    let users = [];
    if (userIds.length) {
      const { data: userData } = await supabase.from("users").select("id, username, email").in("id", userIds);
      users = userData || [];
    }

    const userMap = new Map(users.map(u => [String(u.id), u]));
    const result = rows.map(review => {
      const user = userMap.get(String(review.user_id));
      return { ...review, username: user?.username || "Müşteri", email: user?.email || "" };
    });

    return res.json({ success: true, reviews: result });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Değerlendirmeler alınamadı." });
  }
});

app.post("/api/reviews", authMiddleware, async (req, res) => {
  try {
    const { productId, rating, comment } = req.body;
    const cleanProductId = Number(productId);
    const cleanRating = Number(rating);
    const cleanComment = String(comment || "").trim();

    if (!Number.isFinite(cleanProductId)) return res.status(400).json({ success: false, message: "Geçersiz ürün." });
    if (!Number.isInteger(cleanRating) || cleanRating < 1 || cleanRating > 5) return res.status(400).json({ success: false, message: "Puan 1 ile 5 arasında olmalıdır." });
    if (!cleanComment) return res.status(400).json({ success: false, message: "Lütfen yorumunuzu yazın." });

    const { data, error } = await supabase
      .from("reviews")
      .insert({ product_id: cleanProductId, user_id: req.user.id, rating: cleanRating, comment: cleanComment })
      .select("id, product_id, user_id, rating, comment, created_at")
      .single();

    if (error) return res.status(500).json({ success: false, message: "Yorum gönderilemedi." });
    return res.status(201).json({ success: true, message: "Değerlendirmeniz başarıyla gönderildi.", review: data });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Yorum gönderilemedi." });
  }
});

app.put("/api/reviews/:id", authMiddleware, async (req, res) => {
  try {
    const reviewId = Number(req.params.id);
    const { comment } = req.body;
    
    if (!Number.isFinite(reviewId)) return res.status(400).json({ success: false, message: "Geçersiz yorum ID." });
    if (!comment || comment.trim() === "") return res.status(400).json({ success: false, message: "Yorum boş olamaz." });

    const { error } = await supabase
      .from("reviews")
      .update({ comment: comment.trim() })
      .eq("id", reviewId);

    if (error) return res.status(500).json({ success: false, message: "Yorum güncellenemedi." });
    return res.json({ success: true, message: "Yorum başarıyla güncellendi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Yorum güncellenemedi." });
  }
});

app.get("/api/admin/reviews", adminMiddleware, async (req, res) => {
  try {
    const { data: reviews, error } = await supabase.from("reviews").select("*").order("created_at", { ascending: false });
    if (error) return res.status(500).json({ success: false, message: "Değerlendirmeler alınamadı." });
    return res.json({ success: true, reviews: reviews || [] });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Değerlendirmeler alınamadı." });
  }
});

app.delete("/api/admin/reviews/:id", adminMiddleware, async (req, res) => {
  try {
    const reviewId = Number(req.params.id);
    if (!Number.isFinite(reviewId)) return res.status(400).json({ success: false, message: "Geçersiz yorum ID." });

    const { error } = await supabase.from("reviews").delete().eq("id", reviewId);
    if (error) return res.status(500).json({ success: false, message: "Yorum silinemedi." });
    return res.json({ success: true, message: "Yorum başarıyla silindi." });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Yorum silinemedi." });
  }
});

// ======================================================
// 404
// ======================================================

app.use((req, res) => {
  res.status(404).json({ success: false, message: "İstek yapılan adres bulunamadı." });
});

// ======================================================
// SERVER
// ======================================================

const PORT = process.env.PORT || 10000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`VELORA backend ${PORT} portunda çalışıyor.`);
});
