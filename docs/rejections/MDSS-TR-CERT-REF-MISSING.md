# MDSS-TR-CERT-REF-MISSING

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-REF-MISSING` |
| Başlık | Sertifika referans bilgisi eksik |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_REF_MISSING`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkCertificateRefs`, `#checkTimestampCertificates` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| Örnek paket | `ESXL1_MM_57` (kök), `ESXL1_MM_59` (alt kök), `ESXL1_MM_91` (zaman damgası kökü) |

## Sorunun özeti

İmza `CompleteCertificateRefs` taşıyor, ancak:

- imzacı zincirindeki bir CA sertifikasının (alt kök veya kök) referansı yok, ya da
- arşiv dışı bir zaman damgasının TSA zincirindeki CA sertifikası ne imzanın doğrulama
  verisinde (`CompleteCertificateRefs` / `CertificateValues`) ne de zaman damgasının
  kendi içinde var. Yalnız güven deposundaki kök referans sayılmaz.

Arayüz bu durumda gerekçenin yanında "Eksik bilginin tamamlanması gerekmektedir"
önerisini (`VALIDATION_EVIDENCE_INCOMPLETE`) gösterir.

`CompleteCertificateRefs` imzacı sertifikasının zincirini kapsar (ETSI TS 101 903
§7.4.1). TSA zinciri farklı bir köke bağlanabilir ve doğrulama verisini damganın
içinde taşıyabilir; TSA iptal verisinde olduğu gibi damganın kendi verisi yeterlidir.
`ESXL1_MM_54` / `_76`'da zaman damgası TS C1 → Root C zincirinden gelir, Root C
damganın içindedir ve imza geçerlidir. `ESXL1_MM_91`'de TS C1 damgası Root C'yi
taşımaz, imzada da yoktur; imza reddedilir.

## Neden DSS yakalamıyor

DSS referans kapsamını denetlemez; kök güven deposundan, alt kök `CertificateValues`'tan bulunur ve imza geçer.

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

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=Valid,CN=Root A",
  "certificateId": "C-79BD…"
}
```

## Giderme

İmzanın `CompleteCertificateRefs` alanına eksik CA sertifikasının özet ve düzenleyici/seri numarası referansı eklenmeli (imza yeniden -C/-XL seviyesine yükseltilmeli). Zaman damgası zincirinde eksik CA sertifikası zaman damgasının içine veya imzanın `CertificateValues` alanına eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
