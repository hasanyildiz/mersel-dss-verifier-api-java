# MDSS-TR-OCSP-RESPONDER-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-OCSP-RESPONDER-INVALID` |
| Başlık | OCSP sertifikası geçersiz |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#evaluateRevocation` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (her seviyede, esnek); uzun dönemli imzada ayrıca `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (sıkı) — ikisi de default `true` |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_33` (süresi dolmuş), `ESXL1_MM_34` (imzası bozuk), `ESXL1_MM_35` (iptal), `ESXL1_MM_23` |

## Sorunun özeti

İmzadaki OCSP cevabını imzalayan sertifika cevabın üretildiği anda geçerli değil:

- geçerlilik süresi dolmuş veya henüz başlamamış,
- kendi imzası düzenleyicisiyle doğrulanamıyor,
- imzadaki iptal verisine göre cevap üretilmeden önce iptal edilmiş
  (`id-pkix-ocsp-nocheck` taşıyan sertifikada iptal aranmaz; OCSP sertifikasının
  iptal verisi zorunlu değildir, varsa değerlendirilir).

OCSP sertifikası cevaptan **sonra** iptal edildiyse imza geçerlidir ve
`ARCHIVE_REQUIRED_REVOCATION_EVIDENCE` önerisi verilir (`ESXL1_MM_43`, `_46`).

## Neden DSS yakalamıyor

DSS bu OCSP cevabını kabul edilemez sayar ama başka bir kaynaktan geçerli veri bulduğunda imzayı geçirir; alt kök için ilgili politika kuralları WARN'dur.

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
  "responderSubject": "C=TR,O=Expired,CN=OCSP A4",
  "responderNotAfter": "2019-05-30T07:15:31Z",
  "productionDate": "2023-01-05T09:01:29Z"
}
```

## Giderme

Geçerli bir OCSP sertifikasıyla imzalanmış cevap eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
