package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * HTTP status reddini ({@link UnacceptableHttpStatusException}) gören SİL/AIA
 * indirmesinde aynı isteği {@code Accept-Encoding} başlığı <b>olmadan</b> bir
 * kez daha deneyen, başarılı olursa hostu kalıcı olarak sıkıştırmasız moda
 * alan {@link CommonsDataLoader}.
 *
 * <p><b>Neden:</b> Apache HttpClient 5 varsayılan olarak
 * {@code Accept-Encoding: gzip, x-gzip, deflate} gönderir. Bazı depo
 * sunucuları (ör. KamuSM test deposu {@code depo.test3.kamusm.gov.tr}) bu
 * başlıkla gelen isteği yönlendirip {@code 400} ile reddediyor; sıkıştırma
 * istemeden yapılan istek ise {@code 200} dönüyor. Sağlayıcı başına davranış
 * farklı olduğundan hangi hostun sıkıştırma reddettiği otomatik öğrenilir:</p>
 *
 * <ol>
 *   <li>İlk istek standart davranışla (gzip) gider — sıkıştırmayı doğru
 *       destekleyen sağlayıcılardan bant genişliği tasarrufu korunur.</li>
 *   <li>Yanıt HTTP status hatasıysa ({@link #isHttpStatusRejection}) istek
 *       sıkıştırmasız bir kez daha denenir. Zaman aşımı / bağlantı hatası
 *       gibi sıkıştırmadan bağımsız hatalarda ikinci deneme <b>yapılmaz</b>
 *       (her fetch iki kat zaman aşımı yaşamasın diye).</li>
 *   <li>Sıkıştırmasız deneme başarılıysa host hatırlanır; o hosta sonraki
 *       istekler doğrudan sıkıştırmasız gider (host başına yalnız bir kez
 *       fazladan istek maliyeti).</li>
 *   <li>Sıkıştırmasız deneme de HTTP status hatası aldıysa host "fallback
 *       işe yaramıyor" olarak öğrenilir; sonraki fetch'ler tek istekte kalır
 *       (retry'lı hata yollarında istek sayısı şişmesin diye).</li>
 *   <li>İki deneme de HTTP hatasıyla sonuçlanırsa orijinal hata aynen
 *       fırlatılır; host hatırlanmaz (hata geçici olabilir).</li>
 * </ol>
 *
 * <p>Thread-safe: öğrenilen host seti {@link ConcurrentHashMap} tabanlıdır;
 * fallback denemesi {@code ThreadLocal} bayrakla yalnız kendi isteğinin
 * client builder'ını etkiler. Fast-fail modunda
 * {@code RevocationServicesConfiguration} response handler'ı
 * {@link StatusAwareHttpClientResponseHandler} ile değiştirir; tespit aynı
 * exception tipi üzerinden çalışmaya devam eder (constructor'da zaten aynı
 * handler kurulur).</p>
 */
public class AdaptiveCompressionDataLoader extends CommonsDataLoader {

    private static final long serialVersionUID = 1L;
    private static final Logger logger = LoggerFactory.getLogger(AdaptiveCompressionDataLoader.class);

    /** HTTP status hatasıyla sıkıştırılmış isteği reddeden hostlar. */
    private final Set<String> identityOnlyHosts = ConcurrentHashMap.newKeySet();

    /** Sıkıştırmasız denemenin de HTTP status hatası aldığı hostlar: fallback bir daha denenmez. */
    private final Set<String> fallbackHopelessHosts = ConcurrentHashMap.newKeySet();

    /** Yalnız fallback denemesi süresince true: builder sıkıştırma istemez. */
    private final ThreadLocal<Boolean> identityAttempt = ThreadLocal.withInitial(() -> Boolean.FALSE);

    public AdaptiveCompressionDataLoader() {
        // HTTP status reddi cause zincirinde tipli görünsün ki yalnız status
        // hatalarında (bağlantı/zaman aşımı hatalarında değil) fallback tetiklensin.
        setHttpClientResponseHandler(new StatusAwareHttpClientResponseHandler());
    }

    @Override
    protected synchronized HttpClientBuilder getHttpClientBuilder(String url) {
        HttpClientBuilder builder = super.getHttpClientBuilder(url);
        if (identityAttempt.get() || identityOnlyHosts.contains(hostOf(url))) {
            return builder.disableContentCompression();
        }
        return builder;
    }

    @Override
    public byte[] get(String url) {
        String host = hostOf(url);
        if (identityOnlyHosts.contains(host)) {
            return super.get(url);
        }
        try {
            return super.get(url);
        } catch (RuntimeException e) {
            if (!isHttpStatusRejection(e) || fallbackHopelessHosts.contains(host)) {
                throw e;
            }
            byte[] data = getWithoutCompression(url);
            if (data != null) {
                identityOnlyHosts.add(host);
                logger.info("Sunucu sıkıştırılmış isteği reddediyor; host artık sıkıştırmasız isteniyor: {}", host);
                return data;
            }
            throw e;
        }
    }

    private byte[] getWithoutCompression(String url) {
        identityAttempt.set(Boolean.TRUE);
        try {
            return super.get(url);
        } catch (RuntimeException retry) {
            if (isHttpStatusRejection(retry)) {
                fallbackHopelessHosts.add(hostOf(url));
                logger.info("Sıkıştırmasız istek de HTTP hatası aldı; bu host için fallback bir daha denenmez: {}",
                        hostOf(url));
            }
            logger.debug("SİL/AIA indirmesi sıkıştırmasız denemede de başarısız ({}): {}", url, retry.toString());
            return null;
        } finally {
            identityAttempt.remove();
        }
    }

    /**
     * Hata zincirinde HTTP status reddi ({@link UnacceptableHttpStatusException})
     * var mı? Bağlantı reddi / zaman aşımı gibi sıkıştırmadan bağımsız hatalar
     * için false döner; bu durumda gereksiz ikinci deneme yapılmaz.
     */
    static boolean isHttpStatusRejection(Throwable error) {
        for (Throwable t = error; t != null; t = (t.getCause() == t ? null : t.getCause())) {
            if (t instanceof UnacceptableHttpStatusException) {
                return true;
            }
        }
        return false;
    }

    /** Host anahtarı; ayrıştırılamayan URL'lerde kendisi anahtar olur. */
    static String hostOf(String url) {
        try {
            String host = URI.create(url == null ? "" : url.trim()).getHost();
            return host != null ? host : String.valueOf(url);
        } catch (RuntimeException e) {
            return String.valueOf(url);
        }
    }
}
