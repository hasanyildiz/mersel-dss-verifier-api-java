package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.mersel.dss.verify.api.models.enums.RejectionCode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bir TR uyum kuralının imza için ürettiği ret gerekçesi.
 *
 * <p>{@link #getIndication()} / {@link #getSubIndication()} yalnızca DSS imzayı
 * PASSED olarak raporladığında imzaya yazılır; DSS zaten reddetmişse DSS kararı
 * korunur ve bulgu yalnız "neden" sorusunu yanıtlar.</p>
 */
public final class TrComplianceFinding {

    private final RejectionCode code;
    private final String reason;
    private final Indication indication;
    private final SubIndication subIndication;
    private final Map<String, Object> evidence;

    public TrComplianceFinding(RejectionCode code, String reason, Indication indication,
                               SubIndication subIndication, Map<String, Object> evidence) {
        this.code = code;
        this.reason = reason;
        this.indication = indication;
        this.subIndication = subIndication;
        this.evidence = evidence == null
                ? Collections.<String, Object>emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
    }

    public RejectionCode getCode() {
        return code;
    }

    /** İnsan-okur, olaya özgü Türkçe gerekçe (tarihler, OID'ler, sertifika adları dahil). */
    public String getReason() {
        return reason;
    }

    public Indication getIndication() {
        return indication;
    }

    public SubIndication getSubIndication() {
        return subIndication;
    }

    public Map<String, Object> getEvidence() {
        return evidence;
    }

    @Override
    public String toString() {
        return code.getCode() + ": " + reason;
    }
}
