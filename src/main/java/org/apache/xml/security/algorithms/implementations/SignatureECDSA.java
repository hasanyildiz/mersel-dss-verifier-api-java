/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * ⚠️ MERSEL SINIFYOLU GÖLGESİ (CLASSPATH SHADOW) — Apache Santuario xmlsec 3.0.6
 *
 * Bu dosya, xmlsec 3.0.6 jar'indeki
 * org.apache.xml.security.algorithms.implementations.SignatureECDSA
 * sınıfının birebir kopyasıdır ve yalnızca "MERSEL OVERRIDE" bloklarında
 * değişiklik taşır. Spring Boot yükleyicisi BOOT-INF/classes'ı
 * BOOT-INF/lib'den önce yüklediği için bu kopya orijinalin yerine geçer.
 *
 * NEDEN VAR: W3C XMLDSig (RFC 4051) ECDSA SignatureValue'sini raw r||s
 * olarak ister; Türkiye'deki mali mühür / e-imza üreticilerinin bir kısmı
 * (TÜBİTAK kripto süiti EC örnekleri dahil) ASN.1 DER SEQUENCE üretir.
 * Santuario DER değeri raw sanıp ikiye böler ve imza doğrulanamaz. Önceki
 * çözüm (EcdsaXmlSignaturePreprocessor) XML'deki SignatureValue'yu raw'a
 * çeviriyordu; ancak imza zaman damgası özgün SignatureValue baytlarını
 * damgaladığı için zaman damgası mesaj özeti bozuluyordu (ES-T / -XL / -A
 * EC imzalar geçersiz). Bu gölge belgeyi değiştirmeden DER değeri doğrular.
 *
 * KAPSAM: Yalnız engineVerify. Değer, uzunlukları birebir tutan bir DER
 * SEQUENCE { INTEGER r, INTEGER s } ise kanonik DER olarak JCA'ya verilir
 * (sabit genişlikli INTEGER'lar eski preprocessor gibi kabul edilir); aksi
 * halde orijinal raw → ASN.1 dönüşümü uygulanır. İmza üretimi (engineSign)
 * değişmez.
 *
 * SÜRÜM KİLİDİ: xmlsec sürümü (DSS bağımlılığı) değiştiğinde yeni sürümün
 * SignatureECDSA kaynağıyla karşılaştırıp farkları buraya taşımadan geçmeyin.
 *
 * Ayrıntı: docs/dss-overrides.md
 */
package org.apache.xml.security.algorithms.implementations;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.algorithms.SignatureAlgorithmSpi;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.XMLUtils;

/**
 *
 */
public abstract class SignatureECDSA extends SignatureAlgorithmSpi {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureECDSA.class);

    private final Signature signatureAlgorithm;

    /** Length for each integer in signature */
    private int signIntLen = -1;

    /**
     * Converts an ASN.1 ECDSA value to a XML Signature ECDSA Value.
     *
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param asn1Bytes
     * @param rawLen
     * @return the decode bytes
     *
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertASN1toXMLDSIG(byte[] asn1Bytes, int rawLen) throws IOException {
        return ECDSAUtils.convertASN1toXMLDSIG(asn1Bytes, rawLen);
    }

    /**
     * Converts a XML Signature ECDSA Value to an ASN.1 DSA value.
     *
     * The JAVA JCE ECDSA Signature algorithm creates ASN.1 encoded (r, s) value
     * pairs; the XML Signature requires the core BigInteger values.
     *
     * @param xmldsigBytes
     * @return the encoded ASN.1 bytes
     *
     * @throws IOException
     * @see <A HREF="http://www.w3.org/TR/xmldsig-core/#dsa-sha1">6.4.1 DSA</A>
     * @see <A HREF="ftp://ftp.rfc-editor.org/in-notes/rfc4050.txt">3.3. ECDSA Signatures</A>
     */
    public static byte[] convertXMLDSIGtoASN1(byte[] xmldsigBytes) throws IOException {
        return ECDSAUtils.convertXMLDSIGtoASN1(xmldsigBytes);
    }

    /**
     * Constructor SignatureRSA
     *
     * @throws XMLSignatureException
     */
    public SignatureECDSA() throws XMLSignatureException {
        this(null);
    }

    public SignatureECDSA(Provider provider) throws XMLSignatureException {
        String algorithmID = JCEMapper.translateURItoJCEID(this.engineGetURI());
        LOG.debug("Created SignatureECDSA using {}", algorithmID);

        try {
            if (provider == null) {
                String providerId = JCEMapper.getProviderId();
                if (providerId == null) {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID);

                } else {
                    this.signatureAlgorithm = Signature.getInstance(algorithmID, providerId);
                }

            } else {
                this.signatureAlgorithm = Signature.getInstance(algorithmID, provider);
            }

        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            Object[] exArgs = { algorithmID, ex.getLocalizedMessage() };
            throw new XMLSignatureException("algorithms.NoSuchAlgorithm", exArgs);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws XMLSignatureException {
        try {
            this.signatureAlgorithm.setParameter(params);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected boolean engineVerify(byte[] signature) throws XMLSignatureException {
        try {
            // MERSEL OVERRIDE: DER kodlu değer belge değiştirilmeden doğrulanır (bkz. dosya başı).
            byte[] jcebytes = derEcdsaSignature(signature);
            if (jcebytes == null) {
                jcebytes = SignatureECDSA.convertXMLDSIGtoASN1(signature);
            }

            if (LOG.isDebugEnabled()) {
                LOG.debug("Called ECDSA.verify() on " + XMLUtils.encodeToString(signature));
            }

            return this.signatureAlgorithm.verify(jcebytes);
        } catch (SignatureException | IOException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    // MERSEL OVERRIDE başlangıç -------------------------------------------------

    /**
     * Değer bir DER {@code SEQUENCE { INTEGER r, INTEGER s }} ise JCA'ya verilecek kanonik
     * DER'i, değilse {@code null} (raw r||s) döner. Tüm uzunluklar birebir tutmalı, sonda
     * fazla bayt olmamalı: raw değerin bu yapıya tesadüfen uyması pratikte imkânsızdır;
     * JCA {@code verify} tek seferlik olduğundan biçim önceden kesin seçilmelidir.
     * Kaldırılan EcdsaXmlSignaturePreprocessor gibi INTEGER'lar işaretsiz büyüklük olarak
     * okunur: sabit genişlikli (gereksiz baştaki sıfırlı veya işaret baytı eksik) kodlamalar
     * da kanonik DER'e çevrilir. Kanonik girdi aynı baytlarla döner.
     */
    static byte[] derEcdsaSignature(byte[] value) throws IOException {
        if (value == null || value.length < 8 || (value[0] & 0xff) != 0x30) {
            return null;
        }
        int[] position = {1};
        int sequenceLength = derLength(value, position);
        if (sequenceLength < 0 || position[0] + sequenceLength != value.length) {
            return null;
        }
        byte[][] magnitudes = new byte[2][];
        for (int i = 0; i < 2; i++) {
            if (position[0] >= value.length || (value[position[0]++] & 0xff) != 0x02) {
                return null;
            }
            int integerLength = derLength(value, position);
            if (integerLength <= 0 || position[0] + integerLength > value.length) {
                return null;
            }
            int first = position[0];
            position[0] += integerLength;
            while (first < position[0] && value[first] == 0) {
                first++;
            }
            magnitudes[i] = java.util.Arrays.copyOfRange(value, first, position[0]);
        }
        if (position[0] != value.length) {
            return null;
        }
        if (magnitudes[0].length == 0 || magnitudes[1].length == 0) {
            return value; // r veya s sıfır: JCA reddeder
        }
        int size = Math.max(magnitudes[0].length, magnitudes[1].length);
        byte[] raw = new byte[2 * size];
        System.arraycopy(magnitudes[0], 0, raw, size - magnitudes[0].length, magnitudes[0].length);
        System.arraycopy(magnitudes[1], 0, raw, 2 * size - magnitudes[1].length, magnitudes[1].length);
        return SignatureECDSA.convertXMLDSIGtoASN1(raw);
    }

    /** DER uzunluk alanı (kısa biçim veya 0x81 / 0x82 uzun biçim); geçersizse -1. */
    private static int derLength(byte[] value, int[] position) {
        if (position[0] >= value.length) {
            return -1;
        }
        int first = value[position[0]++] & 0xff;
        if (first < 0x80) {
            return first;
        }
        int octets = first & 0x7f;
        if (octets < 1 || octets > 2 || position[0] + octets > value.length) {
            return -1;
        }
        int length = 0;
        for (int i = 0; i < octets; i++) {
            length = (length << 8) | (value[position[0]++] & 0xff);
        }
        return length;
    }

    // MERSEL OVERRIDE sonu ------------------------------------------------------

    /** {@inheritDoc} */
    @Override
    protected void engineInitVerify(Key publicKey) throws XMLSignatureException {
        engineInitVerify(publicKey, signatureAlgorithm);
    }

    /** {@inheritDoc} */
    @Override
    protected byte[] engineSign() throws XMLSignatureException {
        try {
            byte[] jcebytes = this.signatureAlgorithm.sign();

            return SignatureECDSA.convertASN1toXMLDSIG(jcebytes, signIntLen);
        } catch (SignatureException | IOException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(Key privateKey, SecureRandom secureRandom)
        throws XMLSignatureException {
        if (privateKey instanceof ECPrivateKey) {
            ECPrivateKey ecKey = (ECPrivateKey) privateKey;
            signIntLen = (ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
           // If not ECPrivateKey, signIntLen remains -1
        }
        engineInitSign(privateKey, secureRandom, this.signatureAlgorithm);
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(Key privateKey) throws XMLSignatureException {
        engineInitSign(privateKey, (SecureRandom)null);
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte[] input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte input) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(input);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected void engineUpdate(byte[] buf, int offset, int len) throws XMLSignatureException {
        try {
            this.signatureAlgorithm.update(buf, offset, len);
        } catch (SignatureException ex) {
            throw new XMLSignatureException(ex);
        }
    }

    /** {@inheritDoc} */
    @Override
    protected String engineGetJCEAlgorithmString() {
        return this.signatureAlgorithm.getAlgorithm();
    }

    /** {@inheritDoc} */
    @Override
    protected String engineGetJCEProviderName() {
        return this.signatureAlgorithm.getProvider().getName();
    }

    /** {@inheritDoc} */
    @Override
    protected void engineSetHMACOutputLength(int HMACOutputLength)
        throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.HMACOutputLengthOnlyForHMAC");
    }

    /** {@inheritDoc} */
    @Override
    protected void engineInitSign(
        Key signingKey, AlgorithmParameterSpec algorithmParameterSpec
    ) throws XMLSignatureException {
        throw new XMLSignatureException("algorithms.CannotUseAlgorithmParameterSpecOnRSA");
    }

    /**
     * Class SignatureECDSASHA1
     *
     */
    public static class SignatureECDSASHA1 extends SignatureECDSA {
        /**
         * Constructor SignatureECDSASHA1
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA1() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA1(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA1;
        }
    }

    /**
     * Class SignatureECDSASHA224
     */
    public static class SignatureECDSASHA224 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA224
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA224() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA224(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA224;
        }
    }

    /**
     * Class SignatureECDSASHA256
     *
     */
    public static class SignatureECDSASHA256 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA256
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA256() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA256(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
        }
    }

    /**
     * Class SignatureECDSASHA384
     *
     */
    public static class SignatureECDSASHA384 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA384
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA384() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA384(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384;
        }
    }

    /**
     * Class SignatureECDSASHA512
     *
     */
    public static class SignatureECDSASHA512 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA512
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA512() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA512(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512;
        }
    }

    /**
     * Class SignatureECDSASHA3-224
     *
     */
    public static class SignatureECDSASHA3_224 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA3-224
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA3_224() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA3_224(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_224;
        }
    }

    /**
     * Class SignatureECDSASHA3-256
     *
     */
    public static class SignatureECDSASHA3_256 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA3-256
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA3_256() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA3_256(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_256;
        }
    }

    /**
     * Class SignatureECDSASHA3-384
     *
     */
    public static class SignatureECDSASHA3_384 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA3-384
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA3_384() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA3_384(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_384;
        }
    }

    /**
     * Class SignatureECDSASHA3-512
     *
     */
    public static class SignatureECDSASHA3_512 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSASHA3-512
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSASHA3_512() throws XMLSignatureException {
            super();
        }

        public SignatureECDSASHA3_512(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA3_512;
        }
    }

    /**
     * Class SignatureECDSARIPEMD160
     */
    public static class SignatureECDSARIPEMD160 extends SignatureECDSA {

        /**
         * Constructor SignatureECDSARIPEMD160
         *
         * @throws XMLSignatureException
         */
        public SignatureECDSARIPEMD160() throws XMLSignatureException {
            super();
        }

        public SignatureECDSARIPEMD160(Provider provider) throws XMLSignatureException {
            super(provider);
        }

        /** {@inheritDoc} */
        @Override
        public String engineGetURI() {
            return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_RIPEMD160;
        }
    }

}
