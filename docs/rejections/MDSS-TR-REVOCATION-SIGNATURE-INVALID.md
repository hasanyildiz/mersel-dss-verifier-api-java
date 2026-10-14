# MDSS-TR-REVOCATION-SIGNATURE-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-REVOCATION-SIGNATURE-INVALID` |
| Başlık | İptal bilgisinin imzası bozuk |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_REVOCATION_SIGNATURE_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#evaluateRevocation` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (her seviyede, esnek); uzun dönemli imzada ayrıca `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (sıkı) — ikisi de default `true` |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_29` (alt kök SİL'i), `ESXL1_MM_32` (alt kök OCSP cevabı), `ESXL1_MM_20`, `ESXL1_MM_56` (zaman damgası SİL'i) |

## Sorunun özeti

İmzadaki SİL'in veya OCSP cevabının imzası düzenleyicisiyle doğrulanamıyor. DSS bozuk SİL'i hiçbir sertifikaya bağlayamaz; kural bu durumda imzadaki ham SİL'leri düzenleyici DN'ine göre bulup imzasını kendisi doğrular.

## Neden DSS yakalamıyor

DSS bozuk veriyi yok sayar ve aynı sertifika için başka (zaman damgası içindeki veya çevrimiçi) veri kullanır.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Sıkı referans kullanımı

TÜBİTAK ön hazırlık kılavuzu MA3 kullanıcılarından `xmlsignature-config.xml`
içinde `force-strict-reference-use=true` ister: uzun dönemli imzada (-C / -X /
-XL / -A) sertifika doğrulaması imzanın **referans verdiği** veriyle
(`CompleteCertificateRefs`, `CertificateValues`, `RevocationValues`) yapılır.
DSS ise bir sertifika için bulduğu en iyi veriyi seçer: imzadaki veri bozuk,
süresi dolmuş veya eksikse zaman damgası içindeki SİL'i ya da çevrimiçi yeni
bir cevabı kullanır ve imzayı geçirir. Bu kod imzanın kendi verisini
değerlendirir; başka bir kaynaktaki geçerli veri onu ikame etmez.

## Esnek mod (BES / ES-T)

İmza `RevocationValues` taşımıyorsa (veya sıkı referans kapalıysa) aynı kural DSS'in
bulduğu iptal verisiyle (imzadaki ve çevrimiçi / önbellekteki veri; zaman damgası
içindeki veri yalnız TSA zinciri için) çalışır: geçerli bir veri yeterlidir ve veri
yokluğu tek başına ret nedeni değildir. Ret yalnız olumlu kanıtla verilir: sertifika
kontrol zamanından önce iptal edilmiş ya da bulunan verinin hiçbiri kabul edilebilir
değil (`BES_27`, `EST_27`, `EST_51`, `EST_55`).

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "…",
  "role": "CA",
  "crlIssuer": "C=TR,O=Valid,CN=Root A",
  "crlThisUpdate": "…"
}
```

## Giderme

İmzaya düzenleyicinin geçerli imzalı SİL'i / OCSP cevabı eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
