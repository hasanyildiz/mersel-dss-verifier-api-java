# DSS sınıfyolu gölgeleri (classpath shadow)

Bu proje, DSS politika şemasıyla ifade edilemeyen kurallar için bağımlılık
jar'ındaki sınıfların birebir kopyalarını `src/main/java` altında aynı paket
ve isimle tutar. Spring Boot yükleyicisi `BOOT-INF/classes`'ı
`BOOT-INF/lib`'den önce yüklediği için kopya, DSS'in orijinal sınıfının
yerine geçer.

| Gölge sınıf | DSS sürümü | Değişiklik |
| --- | --- | --- |
| `eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck` | 6.3 | İmzacı sertifikası (`SubContext.SIGNING_CERT`) ve birden fazla beklenen değer varsa `<KeyUsage>` listesi **VE (AND)** olarak değerlendirilir: tüm bit'ler sertifikada bulunmalıdır. Mali mühür sertifikasında (`SignerCertificateProfileDetector` → `MALI_MUHUR`) listedeki `nonRepudiation` aranmaz. CA/TSA zincir sertifikaları ve tek değerli listeler orijinal OR semantiğini korur. |
| `org.apache.xml.security.algorithms.implementations.SignatureECDSA` | xmlsec 3.0.6 (DSS 6.3 bağımlılığı) | `engineVerify`: ECDSA `SignatureValue` uzunlukları birebir tutan bir ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` ise kanonik DER olarak JCA'ya verilir; değilse orijinal raw `r‖s` → DER dönüşümü uygulanır. İmza üretimi değişmez. Bkz. [DER kodlu ECDSA imza değeri](#der-kodlu-ecdsa-imza-değeri). |

## Neden

DSS, `<KeyUsage Level="FAIL">` altındaki `<Id>` listesini
`AbstractMultiValuesCheckItem.processValuesCheck` üzerinden **OR** olarak
değerlendirir: bit'lerden herhangi biri sertifikada varsa kontrol geçer.
Politika XML'inde bu seçeneği ifade eden bir öznitelik yoktur.

## Politika başına davranış (mali mühür ≠ NES/e-imza)

TÜBİTAK doğrulayıcısı mali mühür ve NES/e-imza sertifikalarını ayrı kurallarla
denetler. Profil ayrımı **politika XML'inde değil**, DSS sonrası gate
katmanında OID kanıtlarından tespit edilir
(`SignerCertificateProfileDetector`, ret kodu
[`MDSS-TR-KEYUSAGE-PROFILE`](rejections/MDSS-TR-KEYUSAGE-PROFILE.md)):
e-imza/NES'te `digitalSignature` **ve** `nonRepudiation` birlikte zorunlu,
mali mühürde yalnız `digitalSignature`. Böylece operatörün "mali mühür mü
e-imza mı" politikası seçmesi gerekmez.

Eski politikalar (ör. arayüzün `nonRepudiation` + `digitalSignature` listeleyen
şablonu) bu yüzden geçerli mali mühür imzasını reddetmez: mühür sertifikasında
`nonRepudiation` AND kümesinden çıkarılır, `digitalSignature` yine zorunludur
(`ESXL1_MM_37`).

Built-in politikalar bu yüzden imzacı KeyUsage bloklarında **tek Id**
(`digitalSignature`) listeler — çok değerli liste VE semantiğine
düşeceği için iki Id listelemek mali mühür sertifikalarını (nonRepudiation
taşımaz) yanlışlıkla reddederdi. Gölge sınıf, custom politikalarda imzacı
için birden fazla `<Id>` listelendiğinde VE semantiği sağlamaya devam eder:

| Politika | İmzacı `<KeyUsage>` | Anlamı |
| --- | --- | --- |
| `kamusm-strict-constraint.xml` (`strict`) | `digitalSignature` | Temel zorunluluk; profil kuralı gate'te |
| `kamusm-signer-strict-constraint.xml` (`signer-strict`, varsayılan) | `digitalSignature` | Temel zorunluluk; profil kuralı gate'te |

İki politika sertifika profiline göre değil, iptal kontrolünün sıkılığına göre
ayrılır (bkz. README, politika profilleri); ikisi de hem mali mühür hem
NES/e-imza imzalarını doğrular.

## DER kodlu ECDSA imza değeri

W3C XMLDSig (RFC 4051 §3.4.1) ECDSA `SignatureValue`'sini raw `r‖s` olarak
ister. Mali mühür / e-imza üreticilerinin bir kısmı (TÜBİTAK kripto süitinin
`*_EC256` / `_EC384` / `_EC512` örnekleri dahil) JCA çıktısını, yani ASN.1 DER
`SEQUENCE`'ı yazar. Santuario değeri her zaman raw sanıp ikiye böler; imza
`SIG_CRYPTO_FAILURE` ile düşer.

1.3.1'e kadar `EcdsaXmlSignaturePreprocessor` belgedeki `SignatureValue`'yu
doğrulamadan önce raw'a çeviriyordu. İmza zaman damgası (ES-T ve üstü) özgün
`SignatureValue` baytlarını damgaladığından bu yeniden yazım damganın mesaj
özetini bozuyordu: zaman damgalı her EC imza geçersizdi (BES geçerliydi).
1.3.0 öncesinde TR uyum kapısı bu hatayı `TOTAL_PASSED` göstergesiyle
geçerli gösteriyordu; 1.3.0 göstergeyi karara bağlayınca görünür oldu.

Gölge belgeyi değiştirmez. Etiketleri ve uzunlukları birebir tutan (sonda
fazla bayt olmayan) iki tamsayılı bir `SEQUENCE` DER sayılır; raw `r‖s`'nin bu
kalıba tesadüfen uyması pratikte imkânsızdır. Tamsayılar, kaldırılan
preprocessor'daki gibi işaretsiz büyüklük olarak okunur ve kanonik DER'e
çevrilir: sabit genişlikli (gereksiz baştaki sıfırlı veya işaret baytı eksik)
kodlama üreten imzalayıcılar da doğrulanır. Kurcalanmış değer JCA
doğrulamasında düşer.

## Bakım kuralları

- Her gölge sınıfın başlığında sürüm kılıdı vardır (DSS 6.3). `pom.xml`
  içindeki DSS sürümü yükseltildiğinde yeni sürümün orijinal kaynağıyla
  karşılaştırıp farkları kopyaya taşımadan geçmeyin; imza değişirse derleme
  hatası bunu haber verir.
- Gölge dosyalarında yalnızca `MERSEL OVERRIDE` blokları değişiklik taşır;
  geri kalan her şey yukarı akışla birebir tutulmalıdır (diff kolaylığı için).
- `src/test/java` altındaki aynı paketli testler gölgenin etkin olduğunu
  kanıtlar: `signer_allOf_exactlyOneBitPresent_fails` orijinal DSS sınıfıyla
  geçemezdi.
  `SignatureECDSAShadowTest.derSignatureValue_verifiesWithoutChangingTheDocument`
  orijinal Santuario sınıfıyla geçemezdi.
- `ClasspathShadowGuard` açılışta her gölgenin uygulama sınıflarıyla aynı
  yerden yüklendiğini doğrular; orijinal yüklenmişse (ör. bağımlılıkları önce
  veren bir sınıfyolu) uygulama başlamaz. Yeni gölge eklendiğinde
  `ClasspathShadowGuard.SHADOWS` listesine de eklenir.
- `SignatureECDSA` DSS'in değil xmlsec'in sınıfıdır: DSS yükseltmesi xmlsec
  sürümünü değiştirirse (`mvn dependency:tree | grep xmlsec`) aynı karşılaştırma
  bu kopya için de yapılır.
