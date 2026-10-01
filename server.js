// ======================================================
// PRODUCT REVIEWS
// ======================================================

// Müşteri: Ürünün yorumlarını getir
app.get(
  "/api/reviews/:productId",
  async (req, res) => {
    try {
      const productId = Number(req.params.productId);

      if (!Number.isFinite(productId)) {
        return res.status(400).json({
          success: false,
          message: "Geçersiz ürün ID.",
        });
      }

      const {
        data,
        error,
      } = await supabase
        .from("reviews")
        .select(`
          id,
          product_id,
          user_id,
          rating,
          comment,
          created_at,
          users (
            username
          )
        `)
        .eq("product_id", productId)
        .order("created_at", {
          ascending: false,
        });

      if (error) {
        console.error(
          "Reviews GET hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message: "Değerlendirmeler alınamadı.",
        });
      }

      return res.json({
        success: true,
        reviews: data || [],
      });

    } catch (error) {
      console.error(
        "Reviews GET genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Değerlendirmeler alınamadı.",
      });
    }
  }
);


// Müşteri: Yeni yorum gönder
app.post(
  "/api/reviews",
  authMiddleware,
  async (req, res) => {
    try {
      const {
        productId,
        rating,
        comment,
      } = req.body;

      const cleanProductId =
        Number(productId);

      const cleanRating =
        Number(rating);

      const cleanComment =
        String(comment || "").trim();

      if (
        !Number.isFinite(cleanProductId)
      ) {
        return res.status(400).json({
          success: false,
          message: "Geçersiz ürün.",
        });
      }

      if (
        !Number.isInteger(cleanRating) ||
        cleanRating < 1 ||
        cleanRating > 5
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Puan 1 ile 5 arasında olmalıdır.",
        });
      }

      if (!cleanComment) {
        return res.status(400).json({
          success: false,
          message:
            "Lütfen yorumunuzu yazın.",
        });
      }

      if (cleanComment.length > 1000) {
        return res.status(400).json({
          success: false,
          message:
            "Yorum en fazla 1000 karakter olabilir.",
        });
      }

      const {
        data: product,
        error: productError,
      } = await supabase
        .from("products")
        .select("id")
        .eq("id", cleanProductId)
        .maybeSingle();

      /*
       * Eğer products tablon backend'de yoksa
       * bu kontrolü kaldırabilirsin.
       */
      if (productError) {
        console.error(
          "Ürün kontrol hatası:",
          productError
        );
      }

      if (!product && !productError) {
        return res.status(404).json({
          success: false,
          message:
            "Ürün bulunamadı.",
        });
      }

      const {
        data,
        error,
      } = await supabase
        .from("reviews")
        .insert({
          product_id:
            cleanProductId,

          user_id:
            req.user.id,

          rating:
            cleanRating,

          comment:
            cleanComment,
        })
        .select(`
          id,
          product_id,
          user_id,
          rating,
          comment,
          created_at
        `)
        .single();

      if (error) {
        console.error(
          "Review INSERT hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Yorum gönderilemedi.",
        });
      }

      return res.status(201).json({
        success: true,
        message:
          "Değerlendirmeniz başarıyla gönderildi.",
        review: data,
      });

    } catch (error) {
      console.error(
        "Review POST genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Yorum gönderilemedi.",
      });
    }
  }
);


// ======================================================
// ADMIN REVIEWS
// ======================================================

// Yönetici: Tüm yorumları getir
app.get(
  "/api/admin/reviews",
  async (req, res) => {
    try {
      const {
        data,
        error,
      } = await supabase
        .from("reviews")
        .select(`
          id,
          product_id,
          user_id,
          rating,
          comment,
          created_at,
          users (
            username,
            email
          )
        `)
        .order("created_at", {
          ascending: false,
        });

      if (error) {
        console.error(
          "Admin reviews GET hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Değerlendirmeler alınamadı.",
        });
      }

      return res.json({
        success: true,
        reviews: data || [],
      });

    } catch (error) {
      console.error(
        "Admin reviews genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Değerlendirmeler alınamadı.",
      });
    }
  }
);


// Yönetici: Yorum sil
app.delete(
  "/api/admin/reviews/:id",
  async (req, res) => {
    try {
      const reviewId =
        Number(req.params.id);

      if (!Number.isFinite(reviewId)) {
        return res.status(400).json({
          success: false,
          message:
            "Geçersiz yorum ID.",
        });
      }

      const {
        error,
      } = await supabase
        .from("reviews")
        .delete()
        .eq("id", reviewId);

      if (error) {
        console.error(
          "Admin review DELETE hatası:",
          error
        );

        return res.status(500).json({
          success: false,
          message:
            "Yorum silinemedi.",
        });
      }

      return res.json({
        success: true,
        message:
          "Yorum başarıyla silindi.",
      });

    } catch (error) {
      console.error(
        "Admin review DELETE genel hata:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Yorum silinemedi.",
      });
    }
  }
);
