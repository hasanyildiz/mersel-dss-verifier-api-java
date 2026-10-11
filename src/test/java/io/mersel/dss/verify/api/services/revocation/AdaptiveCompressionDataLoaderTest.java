package io.mersel.dss.verify.api.services.revocation;

import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AdaptiveCompressionDataLoader} host başına otomatik sıkıştırma
 * pazarlığını gerçek HTTP üzerinden doğrular: KamuSM depo sunucusu
 * ({@code depo.test3.kamusm.gov.tr}) {@code Accept-Encoding: gzip} içeren
 * isteği 400 ile reddediyor, sıkıştırmasız isteği 200 ile yanıtlıyor.
 */
class AdaptiveCompressionDataLoaderTest {

    private static final byte[] BODY = "crl-bytes".getBytes(StandardCharsets.US_ASCII);

    private HttpServer server;
    private final AtomicInteger compressedRequests = new AtomicInteger();
    private final AtomicInteger identityRequests = new AtomicInteger();
    /** gzip isteyen isteğe hata dönsün mü (KamuSM senaryosu)? */
    private volatile boolean rejectCompressed;
    /** Tüm isteklere hata dönsün mü (hiç öğrenmemeyi test etmek için)? */
    private volatile boolean rejectAll;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String acceptEncoding = exchange.getRequestHeaders().getFirst("Accept-Encoding");
            if (acceptEncoding == null) {
                identityRequests.incrementAndGet();
            } else {
                compressedRequests.incrementAndGet();
            }
            if (rejectAll || (rejectCompressed && acceptEncoding != null)) {
                exchange.sendResponseHeaders(400, -1);
            } else {
                exchange.sendResponseHeaders(200, BODY.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(BODY);
                }
            }
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void gzipRejectedByServer_fallsBackToIdentity_andRemembersHost() {
        rejectCompressed = true;
        AdaptiveCompressionDataLoader loader = new AdaptiveCompressionDataLoader();

        assertArrayEquals(BODY, loader.get(url()));
        assertEquals(1, compressedRequests.get(), "İlk istek standart (gzip) gider.");
        assertEquals(1, identityRequests.get(), "400 sonrası sıkıştırmasız retry.");

        assertArrayEquals(BODY, loader.get(url()));
        assertEquals(1, compressedRequests.get(), "Host hatırlandı: ikinci çağrıda gzip denenmez.");
        assertEquals(2, identityRequests.get());
    }

    @Test
    void wellBehavedServer_keepsDefaultCompression() {
        AdaptiveCompressionDataLoader loader = new AdaptiveCompressionDataLoader();

        assertArrayEquals(BODY, loader.get(url()));

        assertTrue(compressedRequests.get() >= 1, "Sıkıştırmayı destekleyen sunucuda gzip istenmeye devam edilir.");
        assertEquals(0, identityRequests.get(), "Başarılı istekte sıkıştırmasız fallback olmaz.");
    }

    @Test
    void alwaysRejected_propagatesError_andLearnsFallbackHopeless() {
        rejectAll = true;
        AdaptiveCompressionDataLoader loader = new AdaptiveCompressionDataLoader();

        assertThrows(DSSExternalResourceException.class, () -> loader.get(url()));
        assertEquals(1, compressedRequests.get(), "İlk get: gzip denenir,");
        assertEquals(1, identityRequests.get(), "sonra sıkıştırmasız fallback.");

        assertThrows(DSSExternalResourceException.class, () -> loader.get(url()));
        assertThrows(DSSExternalResourceException.class, () -> loader.get(url()));
        assertEquals(3, compressedRequests.get(), "Fallback işe yaramadı: sonraki get'ler tek istekte kalır.");
        assertEquals(1, identityRequests.get());
    }

    @Test
    void isHttpStatusRejection_distinguishesStatusErrorsFromTransportErrors() {
        assertTrue(AdaptiveCompressionDataLoader.isHttpStatusRejection(new DSSExternalResourceException(
                "wrapped", new UnacceptableHttpStatusException(400, "Not acceptable HTTP Status"))));
        assertFalse(AdaptiveCompressionDataLoader.isHttpStatusRejection(new DSSExternalResourceException(
                "wrapped", new java.io.IOException("Connect timed out"))));
        assertFalse(AdaptiveCompressionDataLoader.isHttpStatusRejection(
                new IllegalStateException("no cause")));
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/SubRootA1_1.crl";
    }
}
