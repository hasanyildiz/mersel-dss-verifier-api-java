/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1307  USA
 */
/*
 * ⚠️ MERSEL SINIFYOLU GÖLGESİ (CLASSPATH SHADOW) — DSS 6.3
 *
 * Bu dosya, dss-validation 6.3 jar'indeki
 * eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck
 * sınıfının birebir kopyasıdır ve yalnızca "MERSEL OVERRIDE" bloklarında
 * değişiklik taşır. Spring Boot yükleyicisi BOOT-INF/classes'ı
 * BOOT-INF/lib'den önce yüklediği için bu kopya DSS'in orijinalinin
 * yerine geçer.
 *
 * NEDEN VAR: DSS, politika XML'indeki <KeyUsage> <Id> listesini OR olarak
 * değerlendirir (AbstractMultiValuesCheckItem.processValuesCheck): listedeki
 * bit'lerden herhangi biri sertifikada varsa kontrol geçer. TÜBİTAK MA3
 * doğrulayıcısının imzacı sertifikası KeyUsage yorumu VE (AND)'dir: örn.
 * nonRepudiation VE digitalSignature'ın ikisi de bulunmalıdır. Politika
 * şemasında bu semantiği ifade etmek mümkün değildir.
 *
 * KAPSAM: AND yorumu YALNIZCA SubContext.SIGNING_CERT için ve beklenen
 * değer listesi birden fazla eleman içerdiğinde uygulanır (ana imzacı ve
 * karşı imza imzacısı). CA ve TSA zincir sertifikaları (SubContext.
 * CA_CERTIFICATE) ile tek değerli listeler orijinal DSS davranışını korur.
 *
 * SÜRÜM KİLİDİ: Bu kopya DSS 6.3'e göre senkron tutulmalıdır. DSS
 * yükseltmelerinde (pom.xml) yeni sürümün KeyUsageCheck kaynağı ile
 * karşılaştırıp farkları buraya taşımadan geçmeyin; orijinal değişirse
 * sınıf imzası çözülür ve derleme hatası bunu haber verir.
 *
 * Ayrıntı: docs/dss-overrides.md
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import io.mersel.dss.verify.api.models.enums.SignerCertificateProfile;
import io.mersel.dss.verify.api.services.util.SignerCertificateProfileDetector;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Checks if the certificate's key usage are acceptable
 *
 * <p>MERSEL OVERRIDE: imzacı sertifikası ({@code SubContext.SIGNING_CERT}) ve
 * birden fazla beklenen değer varsa liste VE (AND) olarak değerlendirilir:
 * tümü sertifikada mevcut olmalıdır. Diğer tüm durumlarda DSS'in OR semantiği
 * korunur.</p>
 */
public class KeyUsageCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

	/** Certificate to check */
	private final CertificateWrapper certificate;

	/** The execution context (e.g. signature, timestamp, etc.) */
	private final Context context;

	/** The execution subContext (e.g. signing-certificate, CA certificate) */
	private final SubContext subContext;

	// MERSEL OVERRIDE: üst sınıf kısıtı private tutar; AND dalı beklenen
	// değer listesini okumak için kendi referansını saklar.
	private final MultiValuesRule expectedKeyUsages;

	// MERSEL OVERRIDE: ValidationProcessUtils.ALL_VALUE gizli ("*"); birebir kopya.
	private static final String ALL_VALUE = "*";

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @param constraint {@link MultiValuesRule}
	 */
	public KeyUsageCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
						 Context context, SubContext subContext, MultiValuesRule constraint) {
		super(i18nProvider, result, constraint);
		this.certificate = certificate;
		this.context = context;
		this.subContext = subContext;
		this.expectedKeyUsages = constraint;
	}

	@Override
	protected boolean process() {
		List<KeyUsageBit> keyUsages = certificate.getKeyUsages();
		List<String> kubStrings = toString(keyUsages);
		// MERSEL OVERRIDE: imzacı sertifikasında çok değerli liste AND'tir.
		if (isSignerAllOfConstraint()) {
			return processAllValuesCheck(kubStrings);
		}
		return processValuesCheck(kubStrings);
	}

	// MERSEL OVERRIDE başlangıç -------------------------------------------------

	/** AND kapsamı: imzacı sertifikası ve birden fazla beklenen değer. */
	private boolean isSignerAllOfConstraint() {
		return SubContext.SIGNING_CERT == subContext
				&& expectedKeyUsages != null
				&& expectedKeyUsages.getValues() != null
				&& expectedKeyUsages.getValues().size() > 1;
	}

	/**
	 * AND yorumu: beklenen her değer sertifikanın key usage listesinde
	 * bulunmalıdır. "*" (any) DSS semantiğiyle herhangi bir mevcut değer
	 * tarafından karşılanır ve zorunlu kümeden çıkarılır. KeyUsage uzantısı
	 * hiç bulunmayan sertifikalar orijinal davranışta olduğu gibi geçemez.
	 *
	 * <p>Mali mühür sertifikasında {@code nonRepudiation} aranmaz: mühür
	 * sertifikaları bu bit'i taşımaz ve profil kuralı (MDSS-TR-KEYUSAGE-PROFILE)
	 * mühürde yalnız digitalSignature ister. Eski politikalar (ör. arayüzün
	 * nonRepudiation + digitalSignature listeleyen şablonu) geçerli mühür
	 * imzalarını bu yüzden reddetmez.</p>
	 */
	private boolean processAllValuesCheck(List<String> values) {
		List<String> expectedValues = expectedKeyUsages.getValues();
		if (expectedValues == null || expectedValues.isEmpty()) {
			return processValuesCheck(values);
		}
		boolean seal = SignerCertificateProfileDetector.detect(certificate) == SignerCertificateProfile.MALI_MUHUR;
		for (String expectedValue : expectedValues) {
			if (ALL_VALUE.equals(expectedValue)) {
				continue;
			}
			if (seal && KeyUsageBit.NON_REPUDIATION.getValue().equals(expectedValue)) {
				continue;
			}
			if (!values.contains(expectedValue)) {
				return false;
			}
		}
		return true;
	}

	// MERSEL OVERRIDE sonu ------------------------------------------------------

	private List<String> toString(List<KeyUsageBit> keyUsages) {
		List<String> result = new ArrayList<>();
		for (KeyUsageBit keyUsageBit : keyUsages) {
			result.add(keyUsageBit.getValue());
		}
		return result;
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.KEY_USAGE, Arrays.toString(certificate.getKeyUsages().toArray()));
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCGKU;
	}

	@Override
	protected XmlMessage buildErrorMessage() {
		if (Context.CERTIFICATE.equals(context)) {
			return buildXmlMessage(MessageTag.BBB_XCV_ISCGKU_ANS_CERT);
		} else {
			return buildXmlMessage(MessageTag.BBB_XCV_ISCGKU_ANS,
					ValidationProcessUtils.getSubContextPosition(subContext),
					ValidationProcessUtils.getContextPosition(context));
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		// CA keyCertSign is a part of RFC 5280, while check of sign-cert falls under AdES validation process
		return SubContext.CA_CERTIFICATE == subContext ? SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE : SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
