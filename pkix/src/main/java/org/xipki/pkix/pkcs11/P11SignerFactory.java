// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs11;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.crypto.DigestOutputStream;
import org.xipki.codec.exception.GenerationException;
import org.xipki.codec.util.StringUtil;
import org.xipki.codec.util.XiArrays;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.Hex;
import org.xipki.pkcs11.wrapper.PKCS11T;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.crypto.core.KeySpec;
import org.xipki.pkix.SecurityFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompKemMlkemVariant;
import org.xipki.crypto.core.composite.CompKemTradVariant;
import org.xipki.crypto.core.composite.CompositeKemSuite;
import org.xipki.crypto.core.composite.CompositeKemUtil;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.KemEncapKey;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.pkcs12.P12XdhMacSignerBuilder;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.DfltConcurrentSigner;
import org.xipki.pkix.sign.KemHmacSigner;
import org.xipki.pkix.sign.SignAlgos;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.sign.SignerConf;
import org.xipki.pkix.sign.SignerFactory;
import org.xipki.crypto.core.EcCurveEnum;
import org.xipki.codec.exception.InvalidConfException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * P11 Signer Factory.
 *
 * @author Lijun Liao (xipki)
 */
public class P11SignerFactory implements SignerFactory {

  private static final String TYPE = "pkcs11";

  private static final Set<String> types = Set.copyOf(Collections.singletonList(TYPE));

  private P11CryptServiceFactory p11CryptServiceFactory;

  public void setP11CryptServiceFactory(P11CryptServiceFactory p11CryptServiceFactory) {
    this.p11CryptServiceFactory = p11CryptServiceFactory;
  }

  @Override
  public Set<String> getSupportedSignerTypes() {
    return types;
  }

  @Override
  public boolean canCreateSigner(String type) {
    return types.contains(type.toLowerCase());
  }

  private P11Key getKey(P11Slot slot, byte[] keyId, String keyLabel) throws GenerationException {
    String str2 = (keyId != null) ? "id " + Hex.encode(keyId) : "label " + keyLabel;
    P11Key key;
    try {
      key = slot.getKey(keyId, keyLabel);
    } catch (TokenException e) {
      throw new GenerationException("error finding identity with "
          + str2 + ": " + e.getMessage(), e);
    }

    if (key == null) {
      throw new GenerationException("unknown identity with " + str2);
    }
    return key;
  }

  @Override
  public ConcurrentSigner newSigner(
      SecurityFactory securityFactory, String type, SignerConf conf, X509Cert[] certificateChain)
      throws GenerationException {
    if (!TYPE.equalsIgnoreCase(type)) {
      throw new GenerationException("unknown signer type " + type);
    }

    if (p11CryptServiceFactory == null) {
      throw new GenerationException("p11CryptServiceFactory is not set");
    }

    if (securityFactory == null) {
      throw new GenerationException("securityFactory could not be null");
    }

    Integer iParallelism;
    try {
      iParallelism = conf.parallelism();
    } catch (InvalidConfException e) {
      throw new GenerationException(e);
    }

    int parallelism = Objects.requireNonNullElseGet(iParallelism,
        securityFactory::dfltSignerParallelism);

    String moduleName = conf.module();
    Integer slotIndex = conf.slot();

    Long slotId = conf.slotId();

    if ((slotIndex == null) == (slotId == null)) {
      throw new GenerationException("exactly one of slot (index) and slot-id must be specified");
    }

    String keyLabel = conf.keyLabel();
    byte[] keyId = conf.keyId();

    if ((keyId == null) == (keyLabel == null)) {
      throw new GenerationException("exactly one of key-id and key-label must be specified");
    }

    P11Slot slot;
    try {
      P11Module module = p11CryptServiceFactory.getP11Module(moduleName);
      P11SlotId p11SlotId = (slotId != null) ? module.getSlotIdForId(slotId)
          : module.getSlotIdForIndex(slotIndex);
      slot = module.getSlot(p11SlotId);
    } catch (TokenException | XiSecurityException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }

    // check whether it is a composite key
    boolean composite = false;
    if (keyLabel != null) {
      composite = StringUtil.startsWithIgnoreCase(keyLabel, P11CompositeKey.COMPOSITE_LABEL_PREFIX);
    }

    try {
      SignAlgo algo = conf.algo();

      P11Key key = null;
      P11CompositeKey compositeKey = null;
      if (composite) {
        String coreLabel = keyLabel.substring(P11CompositeKey.COMPOSITE_LABEL_PREFIX.length());
        P11Key pqcKey = getKey(slot, null,
                        P11CompositeKey.COMP_PQC_LABEL_PREFIX + coreLabel);
        P11Key tradKey = getKey(slot, null,
                        P11CompositeKey.COMP_TRAD_LABEL_PREFIX + coreLabel);
        if (pqcKey.keySpec().isMldsa()) {
          // composite MLDSA
          CompositeSigSuite algoSuite = algo == null ? null : algo.compositeSigAlgoSuite();
          compositeKey = new P11CompositeKey(pqcKey, tradKey, algoSuite);

          if (algo == null) {
            algo = SignAlgos.getInstance(compositeKey, conf);
          }
        } else if (pqcKey.keySpec().isMlkem()) {
          // composite MLKEM
          compositeKey = new P11CompositeKey(pqcKey, tradKey, (CompositeKemSuite) null);
          algo = SignAlgo.KEM_HMAC_SHA256;
        }
      } else {
        key = getKey(slot, keyId, keyLabel);
        if (key.key().id().getKeyType() == PKCS11T.CKK_EC_MONTGOMERY) {
          // X25519, X448: cannot sign, proof of possession with a MAC (DH POP, RFC 6955)
          return newXdhMacSigner(conf, key, certificateChain, parallelism);
        }

        if (algo == null) {
          algo = SignAlgos.getInstance(key, conf);
        }
      }

      List<Signer> signers = new ArrayList<>(parallelism);
      PublicKey publicKey = null;
      if (certificateChain != null && certificateChain.length > 0) {
        publicKey = certificateChain[0].publicKey();
      }

      for (int i = 0; i < parallelism; i++) {
        Signer signer;
        if (compositeKey != null) {
          if (compositeKey.sigAlgoSuite() != null) {
            // Composite MLDSA
            signer = P11CompositeMLDSASigner.newInstance(securityFactory,
                compositeKey, conf, algo, publicKey);
          } else {
            SubjectPublicKeyInfo publicKeyInfo =
                SubjectPublicKeyInfo.fromPublicKey(compositeKey.publicKey());
            KemEncapKey encapKey =
                securityFactory.csrControl().generateKemEncapKey(publicKeyInfo);
            signer = new P11CompositeMLKEMSigner(compositeKey, algo, encapKey);
          }
        } else {
          signer = P11Signer.newInstance(securityFactory, key, conf, algo, publicKey);
        }

        signers.add(signer);
      }

      DfltConcurrentSigner concurrentSigner = new DfltConcurrentSigner(algo.isMac(), signers);

      if (certificateChain != null) {
        concurrentSigner.setX509CertChain(certificateChain);
      } else {
        concurrentSigner.setPublicKey(key != null ? key.publicKey() : compositeKey.publicKey());
      }

      if (algo.isMac()) {
        assert key != null;
        byte[] sha1HashOfKey = key.digestSecretKey(PKCS11T.CKM_SHA_1);
        concurrentSigner.setSha1DigestOfMacKey(sha1HashOfKey);
      }

      return concurrentSigner;
    } catch (TokenException | NoSuchAlgorithmException | InvalidConfException |
             XiSecurityException | CodecException ex) {
      throw new GenerationException(ex.getMessage(), ex);
    }
  } // method newSigner

  /**
   * Creates the DH POP signer (RFC 6955) for an X25519 or X448 key. The shared secret with the
   * static DH key of the peer (CA) is computed in the token with CKM_ECDH1_DERIVE, the MAC is
   * computed in software.
   */
  private static ConcurrentSigner newXdhMacSigner(
      SignerConf conf, P11Key key, X509Cert[] certificateChain, int parallelism)
      throws GenerationException, TokenException, XiSecurityException {
    KeySpec keySpec = key.keySpec();
    EcCurveEnum curve = (keySpec == KeySpec.X25519) ? EcCurveEnum.X25519
        : (keySpec == KeySpec.X448) ? EcCurveEnum.X448 : null;
    if (curve == null) {
      throw new GenerationException("unsupported key " + keySpec);
    }

    // peer certificate is needed
    List<X509Cert> peerCerts = conf.peerCertificates();
    if (peerCerts == null || peerCerts.isEmpty()) {
      throw new GenerationException("no peer certificate is specified");
    }

    X509Cert peerCert = null;
    for (X509Cert m : peerCerts) {
      if (KeyInfoUtil.getCurve(m.publicKey()) == curve) {
        peerCert = m;
        break;
      }
    }

    if (peerCert == null) {
      throw new GenerationException("could not find peer certificate with " + curve + " key");
    }

    byte[] peerPublicKey = peerCert.subjectPublicKeyInfo().subjectPublicKey();
    int zzLen = (curve == EcCurveEnum.X25519) ? 32 : 56;
    byte[] zz = key.deriveKey(PKCS11T.CKM_ECDH1_DERIVE,
        new P11Params.P11Ecdh1DeriveParams(PKCS11T.CKD_NULL, null, peerPublicKey), zzLen);

    PublicKey publicKey = (certificateChain != null && certificateChain.length > 0)
        ? certificateChain[0].publicKey() : key.publicKey();
    try {
      return new P12XdhMacSignerBuilder(curve, zz, peerCert, publicKey, certificateChain)
          .createSigner(parallelism);
    } finally {
      Arrays.fill(zz, (byte) 0);
    }
  }

  /**
   * PKCS#11 {@link Signer} for composite signers.
   *
   * @author Lijun Liao (xipki)
   */
  private static class P11CompositeMLDSASigner implements Signer {

    private final DigestOutputStream os;

    private final P11Signer pqcSigner;

    private final P11Signer tradSigner;

    private final CompositeSigSuite algoSuite;

    private final byte[] encodedX509AlgId;

    private final byte[] context;

    private final MyX509Signer x509Signer;

    private P11CompositeMLDSASigner(
        SecurityFactory securityFactory, P11CompositeKey identity, SignerConf conf,
        CompositeSigSuite algoSuite, byte[] context) throws XiSecurityException {
      this.context = context == null ? null : context.clone();
      this.os = new DigestOutputStream(algoSuite.ph().createDigest());
      this.algoSuite = Args.notNull(algoSuite, "algoSuite");

      this.encodedX509AlgId = algoSuite.algId().getEncoded();

      this.pqcSigner = P11Signer.newInstance(securityFactory,
          identity.pqcKey(), conf, algoSuite.pqcVariant().signAlgo(),
          identity.pqcKey().publicKey(), algoSuite.label());
      this.tradSigner = P11Signer.newInstance(securityFactory,
          identity.tradKey(), conf, algoSuite.tradVariant().signAlgo(),
          identity.tradKey().publicKey());
      this.x509Signer = new MyX509Signer();
    }

    @Override
    public final byte[] getEncodedX509AlgId() {
      return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
    }

    @Override
    public ContentSigner x509Signer() {
      return x509Signer;
    }

    private class MyX509Signer implements ContentSigner {

      @Override
      public final AlgorithmIdentifier getAlgorithmIdentifier() {
        return algoSuite.algId();
      }

      @Override
      public OutputStream getOutputStream() {
        os.reset();
        return os;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        byte[] digestValue = os.digest();
        byte[] m_ = CompositeSigUtil.buildM_(algoSuite, context, digestValue);

        try {
          pqcSigner .x509Signer().getOutputStream().write(m_);
          tradSigner.x509Signer().getOutputStream().write(m_);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }

        byte[]  pqcSig =  pqcSigner.x509Signer().getSignature();
        byte[] tradSig = tradSigner.x509Signer().getSignature();
        return XiArrays.concatenate(pqcSig, tradSig);
      }

      @Override
      public byte[] atomicSign(byte[] toBeSignData) throws SignatureException {
        byte[] digestValue = algoSuite.ph().hash(toBeSignData);
        byte[] m_ = CompositeSigUtil.buildM_(algoSuite, context, digestValue);
        byte[]  pqcSig =  pqcSigner.x509Signer().atomicSign(m_);
        byte[] tradSig = tradSigner.x509Signer().atomicSign(m_);
        return XiArrays.concatenate(pqcSig, tradSig);
      }

    }

    static P11CompositeMLDSASigner newInstance(
        SecurityFactory securityFactory, P11CompositeKey key, SignerConf conf,
        SignAlgo signAlgo, PublicKey publicKey) throws XiSecurityException {
      if (publicKey != null) {
        key.setPublicKey(publicKey);
      }
      return new P11CompositeMLDSASigner(securityFactory, key, conf,
          signAlgo.compositeSigAlgoSuite(), null);
    }

  }

  /**
   * PKCS#11 {@link Signer} for composite KEM signers.
   *
   * @author Lijun Liao (xipki)
   */
  private static class P11CompositeMLKEMSigner implements Signer {

    private final byte[] encodedX509AlgId;

    private final KemHmacSigner kemHmacSigner;

    public P11CompositeMLKEMSigner(
        P11CompositeKey identity, SignAlgo signAlgo, KemEncapKey encapKey)
        throws XiSecurityException {
      this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();

      CompositeKemSuite algoSuite = identity.kemAlgoSuite();
      CompKemMlkemVariant mlkemVariant = algoSuite.pqcVariant();
      CompKemTradVariant tradVariant = algoSuite.tradVariant();

      byte[] pk = identity.publicKeyData();
      byte[] ct = encapKey.encapulation().encapKey();
      byte[] mlkemCT  = Arrays.copyOfRange(ct, 0, mlkemVariant.ctSize());
      byte[] tradCT  = Arrays.copyOfRange(ct, mlkemVariant.ctSize(), ct.length);
      byte[] tradPk = Arrays.copyOfRange(pk, mlkemVariant.pkSize(), pk.length);
      byte[] mlkemSS, tradSS;

      try {
        mlkemSS = identity.pqcKey().decapsulateKey(PKCS11T.CKM_ML_KEM, null, mlkemCT, 32);
      } catch (TokenException ex) {
        throw new XiSecurityException("could not compute mlkemSS", ex);
      }

      try {
        if (tradVariant == CompKemTradVariant.RSA2048_OAEP ||
            tradVariant == CompKemTradVariant.RSA3072_OAEP ||
            tradVariant == CompKemTradVariant.RSA4096_OAEP) {
          long ckm = PKCS11T.CKM_RSA_PKCS_OAEP;
          P11Params params = new P11Params.P11RSAPkcsOaepParams(HashAlgo.SHA256, 0, null);
          tradSS = identity.tradKey().decrypt(ckm, params, tradCT);
        } else {
          long ckm = PKCS11T.CKM_ECDH1_DERIVE;
          P11Params params = new P11Params.P11Ecdh1DeriveParams(PKCS11T.CKD_NULL, null, tradCT);
          tradSS = identity.tradKey().deriveKey(ckm, params, tradVariant.ecdhSize());
        }
      } catch (TokenException ex) {
        throw new XiSecurityException("could not compute tradSS", ex);
      }

      byte[] decapKeyValue = CompositeKemUtil.sha3256Kdf(
          mlkemSS, tradSS, tradCT, tradPk, algoSuite.label());

      byte[] macKeyValue = KemUtil.doKemDecryptSecret(decapKeyValue, encapKey.encapulation());
      SecretKey macKey = new SecretKeySpec(macKeyValue, "AES");
      this.kemHmacSigner = new KemHmacSigner(encapKey.id(), macKey);
    }

    @Override
    public final byte[] getEncodedX509AlgId() {
      return Arrays.copyOf(encodedX509AlgId, encodedX509AlgId.length);
    }

    @Override
    public ContentSigner x509Signer() {
      return kemHmacSigner.x509Signer();
    }

  }

}
