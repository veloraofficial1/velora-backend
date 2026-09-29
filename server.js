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


      /* =========================
         SIPARIŞİ SUPABASE'E KAYDET
      ========================= */

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


      /* =========================
         ADMIN E-POSTA BİLDİRİMİ
      ========================= */

      try {

        await sendOrderEmail({

          orderId:
            newOrder.id,

          customerName:
            customerName,

          customerPhone:
            customerPhone,

          customerAddress:
            customerAddress,

          customerNote:
            customerNote || "",

          items:
            items,

          total:
            Number(total) || 0

        });

        console.log(
          `Sipariş e-postası gönderildi. Sipariş #${newOrder.id}`
        );

      } catch (emailError) {

        /*
         * E-posta gönderilemese bile
         * sipariş başarıyla oluşturulmuş
         * sayılır.
         */

        console.error(
          "SIPARIŞ E-POSTASI HATASI:",
          emailError
        );

      }


      /* =========================
         SUCCESS
      ========================= */

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
