# MDSS-TR-SEAL-CERTIFICATE-POLICY

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-SEAL-CERTIFICATE-POLICY` |
| Başlık | Mali mühür sertifika politikası kontrolü başarısız |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_SEAL_CERTIFICATE_POLICY`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkCertificateProfile`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CHAIN_CONSTRAINTS_FAILURE` |
| Örnek paket | `*_39` (MM A1 3, "CP OID Absent") |

## Sorunun özeti

Mali mühür sertifikası (EKU `2.16.792.1.2.1.1.5.7.50.1`) mali mühür politikası `2.16.792.1.2.1.1.5.7.4.1` yerine başka bir politika (örnek pakette NES politikası `…5.7.1.1`) taşıyor.

## Neden DSS yakalamıyor

Politika XML'indeki `PolicyIds` profil koşullu ifade edilemez. Mühür EKU'su profil tespitinde NES politika OID'inin önündedir (`SignerCertificateProfileDetector`); sertifika NES sayılıp nonRepudiation eksikliğiyle yanlış gerekçeyle reddedilmez.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=CP OID Absent,CN=MM A1 3",
  "certificatePolicies": [
    "2.16.792.1.2.1.1.5.7.1.1"
  ],
  "extendedKeyUsages": [
    "2.16.792.1.2.1.1.5.7.50.1"
  ]
}
```

## Giderme

Mali mühür akışında mali mühür politikasını taşıyan sertifika kullanın.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
