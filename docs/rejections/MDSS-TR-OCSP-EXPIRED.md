# MDSS-TR-OCSP-EXPIRED

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-OCSP-EXPIRED` |
| Başlık | OCSP cevabının süresi dolmuş |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_OCSP_EXPIRED`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#ocspCovers` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (her seviyede, esnek); uzun dönemli imzada ayrıca `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (sıkı) — ikisi de default `true` |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_31` (alt kök), `ESXL1_MM_19` (imzacı) |

## Sorunun özeti

İmzadaki OCSP cevabı kontrol zamanındaki (imza zaman damgası) durumu kanıtlamıyor:

- `nextUpdate` varsa kontrol zamanından önce dolmuş, ya da
- `nextUpdate` yoksa cevap kontrol zamanından 24 saatten daha önce üretilmiş
  (`OCSP_FRESHNESS_TOLERANCE_MILLIS`; saat farkı ve damgadan hemen önce alınan
  cevap için pay, imzacı politikasının 24 saatlik `RevocationFreshness` değeriyle aynı).

## Neden DSS yakalamıyor

Alt kök için politikada `RevocationFreshness` IGNORE'dur ve DSS eski cevap yerine zaman damgası içindeki veya çevrimiçi veriyi kullanır.

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
  "revocationType": "OCSP",
  "thisUpdate": "2012-01-01T00:00:00Z",
  "controlTime": "2023-01-05T09:01:03Z"
}
```

## Giderme

İmza zaman damgasından sonra alınmış bir OCSP cevabı eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
