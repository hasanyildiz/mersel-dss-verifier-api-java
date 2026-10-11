# MDSS-TR-KEYUSAGE-PROFILE

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-KEYUSAGE-PROFILE` |
| Başlık | İmzacı sertifikası profilinin KeyUsage gereksinimi karşılanmıyor |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası gate) |
| İlgili enum | [`RejectionCode.MDSS_TR_KEYUSAGE_PROFILE`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`AdvancedSignatureVerificationService#evaluateSignerKeyUsageProfileRejection`](../../src/main/java/io/mersel/dss/verify/api/services/verification/AdvancedSignatureVerificationService.java) |
| Detector | [`SignerCertificateProfileDetector`](../../src/main/java/io/mersel/dss/verify/api/services/util/SignerCertificateProfileDetector.java) |
| Config | `verification.signer-keyusage-profile-enabled` (default: `true`) |

## Sorunun özeti

İmzacı sertifikasının **profili** (mali mühür mü, e-imza/NES mi) operatörün
politika seçimine bırakılamaz; sertifikanın kendi OID kanıtlarından tespit
edilir ve profile uygun KeyUsage kuralı uygulanır. TÜBİTAK doğrulayıcısı da
iki profili farklı denetler.

| Profil | Tespit kanıtları | Zorunlu KeyUsage |
|---|---|---|
| e-imza / NES (QC A*) | politika OID `2.16.792.1.2.1.1.5.7.1.1`; KamuSM QC statement `2.16.792.1.61.0.1.5070.x` | `digitalSignature` **VE** `nonRepudiation` birlikte |
| Mali mühür (MM A*) | politika OID `2.16.792.1.2.1.1.5.7.4.1` **veya** EKU `2.16.792.1.2.1.1.5.7.50.1` (EKU her sertifikada yok); mühür kanıtı NES politika OID'inin önündedir | yalnız `digitalSignature` |
| Belirlenemedi | — | kural uygulanmaz; etkin politikanın kendi KeyUsage constraint'i geçerli |

Örnek paket gerçekleri: QC A\* e-imza sertifikaları iki biti birden taşır;
mali mühür sertifikaları yalnız `digitalSignature` taşır (nonRepudiation
mühürlerde bulunmaz); `ESXL1_MM_7` (QC A1 3) yalnız `digitalSignature`
taşıyan **bilinçli negatif** örnektir ve reddedilmelidir.

## Neden DSS'ten PASSED gelebilir

DSS, politika XML'indeki `<KeyUsage>` `<Id>` listesini **OR** olarak
değerlendirir: bit'lerden herhangi biri varsa kontrol geçer. Dolayısıyla
"yalnız digitalSignature" taşıyan bir NES sertifikası, imzacı için iki Id
listelenmiş bir politikada bile DSS'ten geçebilir. Bu kontrol DSS sonrası
gate katmanında çalışır ve **DSS PASSED dese bile** imzayı reddeder;
DSS'in asıl kararı `AppliedRejection.originalIndication` alanında saklanır.
Karar yalnız DSS imzayı geçirdiyse değişir (`INDETERMINATE` /
`CHAIN_CONSTRAINTS_FAILURE`); DSS zaten reddettiyse (ör. `TOTAL_FAILED` /
`HASH_FAILURE`, `REVOKED`) DSS'in indication, subIndication ve hata satırları
aynen korunur, ihlal yalnız eklenir.
Diğer `MDSS-TR-*` kodları gibi imzanın `rootCause` alanı bu koddur; DSS de
reddettiyse (ör. çok değerli özel politika) jenerik BBB satırının önüne
geçer ve opt-in `failedConstraints` listesinde ilk sırada yer alır.

Politika XML'lerinde (built-in `kamusm-strict` / `kamusm-signer-strict`)
imzacı KeyUsage blokları bu yüzden bilinçli olarak tek Id
(`digitalSignature`) listeler: profil ayrımını DSS politika şemasında
ifade etmek mümkün değildir ve iki Id listelemek mali mühür
sertifikalarını yanlışlıkla reddederdi.

Mühür kanıtı NES politika OID'inin önünde değerlendirilir: NES politikasını
yanlışlıkla taşıyan bir mühür sertifikası (`*_39`, MM A1 3, "CP OID Absent")
NES sayılmaz; nonRepudiation eksikliğiyle yanlış gerekçeyle reddedilmek
yerine TR uyum kontrolündeki
[`MDSS-TR-SEAL-CERTIFICATE-POLICY`](./MDSS-TR-SEAL-CERTIFICATE-POLICY.md)
ile reddedilir.

## TR uyum kontrolleriyle ilişkisi

NES'in diğer nitelik kuralları (UserNotice, ETSI ve BTK QC ibareleri) ve
mali mühür EKU/politika kuralları `TR_COMPLIANCE_CHECKS_ENABLED` bayrağı
arkasındaki `TrComplianceChecker`'dadır. NES nonRepudiation kuralı yalnız
bu kodda yaşar; TR uyum kontrolü aynı vakaya ikinci bir ret eklemez.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "profile": "NES_E_IMZA",
  "profileLabel": "Nitelikli elektronik imza (e-imza/NES)",
  "presentKeyUsageBits": ["digitalSignature"],
  "missingKeyUsageBits": ["nonRepudiation"],
  "signerCommonName": "QC A1 3"
}
```

## Giderme

İmza, sertifikanın profiline uygun yetkideki sertifikayla atılmalıdır:

- e-imza akışlarında `nonRepudiation` (contentCommitment) **ve**
  `digitalSignature` taşıyan nitelikli sertifika kullanın.
- Mali mühür akışında mali mühür sertifikası kullanın; bu ret kodu yalnızca
  mühür sertifikasında `digitalSignature` de yoksa tetiklenir.
- Şifreleme amaçlı düzenlenmiş sertifikalar (keyEncipherment + keyAgreement,
  EKU = TLS Web Client Authentication) XML imzalamada kullanılmamalıdır.

## İlgili

- Sınıfyolu gölgesi (custom politikalarda çok değerli imzacı listeleri VE
  olarak değerlendirilir): [docs/dss-overrides.md](../dss-overrides.md)
- Uyum değerlendirme notları (UI tarafı):
  `mersel-dss-compliance-ui/docs/compliance-matrix.md`
