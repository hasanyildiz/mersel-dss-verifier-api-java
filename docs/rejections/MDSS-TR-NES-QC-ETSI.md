# MDSS-TR-NES-QC-ETSI

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-NES-QC-ETSI` |
| Başlık | NES nitelikli sertifika ibaresi (ETSI) eksik |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_NES_QC_ETSI`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkCertificateProfile`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CHAIN_CONSTRAINTS_FAILURE` |
| Örnek paket | `ESXL1_MM_9` (QC A1 5, "ETSI QC Statement ID Absent") |

## Sorunun özeti

İmzacı NES sertifikasının `qcStatements` uzantısında ETSI QcCompliance ibaresi `0.4.0.1862.1.1` yok (BTK ibaresi var).

### OID'ler ne anlama geliyor

**OID** (Object Identifier), dünya çapında tekil, noktalı bir sayı
dizisidir; sertifikalar "ne olduklarını" bu numaralarla beyan eder. NES
sertifikasında nitelik beyanı iki uzantıda durur:

| Uzantı | OID | NES'te beklenen içerik |
|---|---|---|
| `certificatePolicies` | `2.5.29.32` | Politika OID'i (KamuSM NES: `2.16.792.1.2.1.1.5.7.1.1`) ve altında **kullanıcı bildirimi** (UserNotice, `1.3.6.1.5.5.7.2.2`): "Bu sertifika, 5070 sayılı Elektronik İmza Kanununa göre nitelikli elektronik sertifikadır." |
| `qcStatements` (RFC 3739) | `1.3.6.1.5.5.7.1.3` | Nitelikli sertifika ibareleri: **ETSI** `0.4.0.1862.1.1` (`id-etsi-qcs-QcCompliance`, ETSI EN 319 412-5 — "nitelikli sertifika olarak düzenlendi") ve **BTK** `2.16.792.1.61.0.1.5070.1.1` (ulusal 5070 sayılı Kanun ibaresi, aynı Türkçe metinle). |

Mali mühür sertifikaları bu ibarelerin hiçbirini taşımaz; bu yüzden kural
yalnızca mali mühür olmayan imzacılara uygulanır.

## Neden DSS yakalamıyor

DSS'in `<QcCompliance>` kısıtı bu vakayı yakalar, ancak politika genelinde açılırsa QC ibaresi taşımayan geçerli mali mühür imzalarını da reddeder; DSS politika şeması profil koşullu kural ifade edemez. Kontrol bu yüzden DSS sonrası, yalnız NES profilinde çalışır.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "2.5.4.5=#130b3131313131313131313131,C=TR,O=ETSI QC Statement ID Absent,CN=QC A1 5",
  "certificatePolicies": [
    "2.16.792.1.2.1.1.5.7.1.1"
  ],
  "keyUsages": [
    "digitalSignature",
    "nonRepudiation"
  ],
  "qcStatements": [
    "1.3.6.1.5.5.7.11.1",
    "2.16.792.1.61.0.1.5070.1.1"
  ]
}
```

## Giderme

İmza, ETSI QcCompliance ibaresini taşıyan nitelikli sertifikayla atılmalıdır.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
