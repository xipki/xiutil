// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.dump;

import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.crl.C509RevokedCertsControl;
import org.xipki.c509.crl.C509RevocationReason;
import org.xipki.c509.ext.C509KeyUsage;
import org.xipki.c509.ext.C509ReasonFlags;
import org.xipki.c509.ext.C509TLSFeatures;
import org.xipki.c509.ipres.C509IPAddressFamily;
import org.xipki.c509.ocsp.C509CertStatus;
import org.xipki.c509.ocsp.C509OCSPRequest;
import org.xipki.c509.ocsp.C509OCSPResponse;
import org.xipki.c509.ocsp.C509ResponseStatus;
import org.xipki.c509.registry.ConstAccessMethod;
import org.xipki.c509.registry.ConstAttributeType;
import org.xipki.c509.registry.ConstCertificateType;
import org.xipki.c509.registry.ConstExtendedKeyUsage;
import org.xipki.c509.registry.ConstExtensionId;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.c509.registry.ConstCertificatePolicy;
import org.xipki.c509.registry.ConstPolicyQualifier;
import org.xipki.c509.registry.ConstRegistry;
import org.xipki.codec.Hex;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.c509.id.ConstPublicKeyAlgorithm;
import org.xipki.codec.c509.id.ConstSignatureAlgorithm;
import org.xipki.codec.cbor.CborDiag;
import org.xipki.codec.cbor.CborType;
import org.xipki.codec.exception.CodecException;

import java.math.BigInteger;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.IntFunction;
import java.util.function.LongFunction;

/**
 * Annotated hex dump of encoded C509 structures: every CBOR item is printed with its offset,
 * its bytes and its meaning.
 * <pre>
 *   C509Dumper.of(certificate).print(System.out);
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public final class C509Dumper extends CborDiag {

  /**
   * The kinds of structures the dumper understands.
   */
  public enum Doc {
    CERTIFICATE,
    CERT_REQUEST,
    REQUEST_TEMPLATE,
    CRL,
    OCSP_REQUEST,
    OCSP_RESPONSE
  }

  /**
   * Prints one value whose type is known from the context.
   */
  @FunctionalInterface
  private interface ValueDumper {
    void dump(int level, String label) throws CodecException;
  }

  /**
   * Numbers the elements of an array: "[0]. name", "[1]. name", ...
   */
  private static final class Counter {

    private int next;

    String label(String name) {
      return "[" + (next++) + "]. " + name;
    }

  }

  private final Doc doc;

  private final Map<Long, ValueDumper> extensionDumpers = new HashMap<>();

  private final Map<Long, ValueDumper> attributeDumpers = new HashMap<>();

  public C509Dumper(Doc doc, byte[] encoded) {
    super(encoded, false);
    this.doc = doc;
    setup();
  }

  public static C509Dumper of(Doc doc, C509CborItem item) {
    return new C509Dumper(doc, item.getEncoded());
  }

  public static C509Dumper of(C509OCSPRequest request) throws CodecException {
    return new C509Dumper(Doc.OCSP_REQUEST, request.getEncoded());
  }

  public static C509Dumper of(C509OCSPResponse response) throws CodecException {
    return new C509Dumper(Doc.OCSP_RESPONSE, response.getEncoded());
  }

  private void setup() {
    setNumSpacesBeforeComment(15);
    setMaxCharsPerLine(69);
    setNumBytesPerLine(30);
    setNumTextBytesPerLine(16);

    ext(this::dumpAsIdentifiers,
        ConstExtensionId.autonomousSysIds, ConstExtensionId.autonomousSysIds_v2);
    ext(this::dumpInfoAccess,
        ConstExtensionId.authorityInfoAccess, ConstExtensionId.subjectInfoAccess);
    ext(this::dumpAuthorityKeyId, ConstExtensionId.authorityKeyIdentifier);
    ext(this::dumpBasicConstraints, ConstExtensionId.basicConstraints);
    ext(this::dumpPolicies, ConstExtensionId.certificatePolicies);
    ext(this::dumpDistPoints, ConstExtensionId.cRLDistributionPoints, ConstExtensionId.freshestCRL);
    ext(this::dumpExtKeyUsage, ConstExtensionId.extKeyUsage);
    ext(this::dumpIpAddrBlocks, ConstExtensionId.ipAddrBlocks, ConstExtensionId.ipAddrBlocks_v2);
    ext(this::dumpAltName, ConstExtensionId.subjectAltName, ConstExtensionId.issuerAltName);
    ext(this::dumpKeyUsage, ConstExtensionId.keyUsage);
    ext(this::dumpAttributes, ConstExtensionId.subjectDirectoryAttributes);
    ext(this::dumpNameConstraints, ConstExtensionId.nameConstraints);
    ext(this::dumpPolicyConstraints, ConstExtensionId.policyConstraints);
    ext(this::dumpPolicyMappings, ConstExtensionId.policyMappings);
    ext(this::dumpTlsFeatures, ConstExtensionId.tlsfeature);
    ext(this::dumpPreferredSigAlgs, ConstExtensionId.ocsp_pref_sig_algs);
    ext((level, label) -> printTextString(level, label), ConstExtensionId.ocsp_stir_tn);

    attributeDumpers.put(ConstAttributeType.challengePassword, this::dumpChallengePassword);
    attributeDumpers.put(ConstAttributeType.extensionRequest,
        (level, label) -> dumpExtensions(level, label + ": extensions"));
    attributeDumpers.put(ConstAttributeType.privateKeyPossessionStatement, this::dumpPossession);
    attributeDumpers.put(ConstAttributeType.changeSubjectName, this::dumpChangeSubjectName);
    attributeDumpers.put(ConstAttributeType.dateOfBirth, (level, label) -> printLong(level, label));
    for (long id : new long[] {ConstAttributeType.placeOfBirth, ConstAttributeType.gender,
        ConstAttributeType.countryOfCitizenship, ConstAttributeType.countryOfResidence}) {
      attributeDumpers.put(id, (level, label) -> printTextString(level, label));
    }
  }

  private void ext(ValueDumper dumper, long... ids) {
    for (long id : ids) {
      extensionDumpers.put(id, dumper);
    }
  }

  @Override
  protected void print0() throws CodecException {
    switch (doc) {
      case CERTIFICATE:
        dumpCertificate();
        break;
      case CERT_REQUEST:
        dumpCertRequest();
        break;
      case REQUEST_TEMPLATE:
        dumpRequestTemplate();
        break;
      case CRL:
        dumpCrl();
        break;
      case OCSP_REQUEST:
        dumpOcspRequest();
        break;
      default:
        dumpOcspResponse();
    }
  }

  // ----- documents -----

  private void dumpCertificate() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509Certificate");
    Counter c = new Counter();
    note(level, c.label("certificateType=" + readInt()));
    printByteString(level, c.label("certificateSerialNumber"));
    int sigAlg = dumpAlgorithm(level, ConstRegistry.SIGNATURE_ALGORITHM,
        c.label("issuerSignatureAlg"));
    dumpName(level, c.label("issuer"));
    dumpTime(level, c.label("notBefore"));
    dumpTime(level, c.label("notAfter"));
    dumpName(level, c.label("subject"));
    int keyAlg = dumpAlgorithm(level, ConstRegistry.PUBLIC_KEY_ALGORITHM,
        c.label("subjectPublicKeyAlg"));
    dumpPublicKey(level, c.label("subjectPublicKey"), keyAlg);
    dumpExtensions(level, c.label("extensions"));
    dumpSignature(level, c.label("issuerSignatureValue"), sigAlg);
  }

  private void dumpCertRequest() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509CertificationRequest");
    Counter c = new Counter();
    note(level, c.label("requestType=" + readInt()));
    int sigAlg = dumpAlgorithm(level, ConstRegistry.SIGNATURE_ALGORITHM,
        c.label("subjectSignatureAlg"));
    dumpName(level, c.label("subject"));
    int keyAlg = dumpAlgorithm(level, ConstRegistry.PUBLIC_KEY_ALGORITHM,
        c.label("subjectPublicKeyAlg"));
    dumpPublicKey(level, c.label("subjectPublicKey"), keyAlg);
    dumpAttributes(level, c.label("attributes"));
    dumpSignature(level, c.label("subjectSignatureValue"), sigAlg);
  }

  private void dumpRequestTemplate() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509CertificationRequestTemplate");
    Counter c = new Counter();
    note(level, c.label("templateType=" + readInt()));
    optional(level, c.label("requestTypes"), (l, label) -> {
      int n = readArrayLength();
      note(l, label + ": array[" + n + "]");
      for (int i = 0; i < n; i++) {
        note(l + 1, "[" + i + "]. type " + readInt());
      }
    });
    optional(level, c.label("subjectSignatureAlgs"),
        (l, label) -> dumpAlgorithmList(l, ConstRegistry.SIGNATURE_ALGORITHM, label));
    optional(level, c.label("subject"), this::dumpNameTemplate);
    optional(level, c.label("subjectPublicKeyAlgs"),
        (l, label) -> dumpAlgorithmList(l, ConstRegistry.PUBLIC_KEY_ALGORITHM, label));
    optional(level, c.label("subjectPublicKey"), this::output);
    optional(level, c.label("extensions"), this::dumpExtensionTemplates);
  }

  private void dumpCrl() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509CertificateList");
    Counter c = new Counter();
    note(level, c.label("crlType=" + readInt()));
    int sigAlg = dumpAlgorithm(level, ConstRegistry.SIGNATURE_ALGORITHM, c.label("signatureAlg"));
    dumpNameVariant(level, c.label("authoritySubject"));
    printByteStringObj(level, c.label("authorityKeyIdentifier"));
    printLong(level, c.label("crlNumber"));
    long thisUpdate = dumpTime(level, c.label("thisUpdate"));
    dumpRelativeTime(level, c.label("nextUpdate"), thisUpdate);
    printLongObj(level, c.label("baseCrlNumber"));
    dumpExtensions(level, c.label("crlExtensions"));

    String label = c.label("revokedCertsList");
    if (peekType().isNull()) {
      printNull(level, label);
    } else {
      int groups = printAndReadArrayLen(level, label) / 5;
      for (int i = 0; i < groups; i++) {
        dumpRevocationGroup(level + 1, i);
      }
    }
    dumpSignature(level, c.label("signatureValue"), sigAlg);
  }

  private void dumpOcspRequest() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509OCSPRequest");
    Counter c = new Counter();
    C509OCSPRequest.Kind kind = C509OCSPRequest.Kind.ofCode(readInt());
    note(level, c.label("requestType=" + kind + " (" + kind.code() + ")"));
    switch (kind) {
      case SIMPLE:
        dumpAlgorithm(level, ConstRegistry.HASH_ALGORITHM, c.label("hashAlg"));
        printByteStringObj(level, c.label("nonce"));
        printByteString(level, c.label("issuerCertHash"));
        printByteString(level, c.label("serialNumberHash"));
        dumpExtensions(level, c.label("extensions"));
        break;
      default: // basic
        CborType cborType = peekType();
        Integer sigAlg = null;
        if (cborType.isNull()) {
          printNull(level, c.label("signatureAlg"));
        } else {
          sigAlg = dumpAlgorithm(level, ConstRegistry.SIGNATURE_ALGORITHM,
              c.label("signatureAlg"));
        }
        dumpAlgorithm(level, ConstRegistry.HASH_ALGORITHM, c.label("hashAlg"));
        printByteStringObj(level, c.label("nonce"));
        dumpExtensions(level, c.label("extensions"));
        dumpIssuerGroups(level, c.label("requests"), "PerIssuerRequest", 0);
        if (sigAlg != null) {
          printByteString(level, c.label("requestorCertHash"));
          dumpCertChain(level, c.label("requestorCerts"));
          dumpSignature(level, c.label("signatureValue"), sigAlg);
        }
    }
  }

  private void dumpOcspResponse() throws CodecException {
    int level = 0;
    printAndReadArrayLen(level++, "C509OCSPResponse");
    Counter c = new Counter();
    C509OCSPResponse.Kind kind = C509OCSPResponse.Kind.ofCode(readInt());
    note(level, c.label("responseType=" + kind + " (" + kind.code() + ")"));
    if (kind == C509OCSPResponse.Kind.ERROR) {
      int status = readInt();
      note(level, c.label("responseStatus=" + C509ResponseStatus.ofCode(status) + " (" + status
          + ")"));
      return;
    }

    int sigAlg = dumpAlgorithm(level, ConstRegistry.SIGNATURE_ALGORITHM, c.label("signatureAlg"));
    dumpAlgorithm(level, ConstRegistry.HASH_ALGORITHM, c.label("hashAlg"));
    printByteStringObj(level, c.label("nonce"));
    printByteString(level, c.label("responderCertHash"));
    if (kind == C509OCSPResponse.Kind.SIMPLE) {
      printByteString(level, c.label("issuerCertHash"));
      printByteString(level, c.label("serialNumberHash"));
      dumpCertStatus(level, c.label("certStatus"));
      long producedAt = dumpTime(level, c.label("producedAt"));
      dumpRelativeTime(level, c.label("thisUpdate"), producedAt);
      dumpRelativeTime(level, c.label("nextUpdate"), producedAt);
      dumpExtensions(level, c.label("extensions"));
    } else {
      long producedAt = dumpTime(level, c.label("producedAt"));
      dumpExtensions(level, c.label("extensions"));
      dumpIssuerGroups(level, c.label("responses"), "PerIssuerResponse", producedAt);
    }
    dumpCertChain(level, c.label("responderCerts"));
    dumpSignature(level, c.label("signatureValue"), sigAlg);
  }

  // ----- building blocks -----

  private void note(int level, String text) throws CodecException {
    writeLine(level, readResetBuffer(), text);
  }

  private void optional(int level, String label, ValueDumper dumper) throws CodecException {
    if (peekType().isUndefined()) {
      readUndefined();
      note(level, label + "=<undefined>");
    } else {
      dumper.dump(level, label);
    }
  }

  private Long dumpTime(int level, String label) throws CodecException {
    if (peekType().isNull()) {
      printNull(level, label);
      return null;
    }
    long t = readLong();
    note(level, label + "=" + t + ": " + Instant.ofEpochSecond(t));
    return t;
  }

  private void dumpRelativeTime(int level, String label, long base) throws CodecException {
    if (peekType().isNull()) {
      printNull(level, label);
    } else {
      long delta = readLong();
      note(level, concat(label, Long.toString(delta)) + ": " + Instant.ofEpochSecond(base + delta));
    }
  }

  private int dumpAlgorithm(int level, ConstRegistry registry, String label) throws CodecException {
    long code = dumpCode(level, registry::nameOf, label, "");
    if (code < Integer.MIN_VALUE || code > Integer.MAX_VALUE) {
      throw new CodecException("algorithm is not a 32-bit integer: " + code);
    }
    return (int) code;
  }

  private void dumpAlgorithmList(int level, ConstRegistry registry, String label)
      throws CodecException {
    int n = readArrayLength();
    note(level, label + ": array[" + n + "]");
    for (int i = 0; i < n; i++) {
      dumpAlgorithm(level + 1, registry, "[" + i + "]. ");
    }
  }

  /**
   * Adapts the name function of a registry with 32-bit codes; codes outside the 32-bit range
   * are reported as unknown.
   */
  private static LongFunction<String> intNamer(IntFunction<String> namer) {
    return code -> (code == (int) code) ? namer.apply((int) code) : "unknown";
  }

  /**
   * Prints an integer code with its name.
   *
   * @param namer returns the name of a code.
   * @param negativeHint appended if the code is negative, e.g. ", critical".
   */
  private long dumpCode(
      int level, LongFunction<String> namer, String label,
      String negativeHint) throws CodecException {
    long code = readLong();
    String text = namer.apply(Math.abs(code)) + (code < 0 ? negativeHint : "")
        + " (" + code + ")";
    String line;
    if (label.isEmpty() || label.endsWith(" ") || label.endsWith("=")) {
      line = label + text;
    } else if (label.endsWith(":") || label.endsWith(".")) {
      line = label + " " + text;
    } else {
      line = label + "=" + text;
    }
    note(level, line);
    return code;
  }

  private void dumpOid(int level, String label) throws CodecException {
    int len = readByteStringLength();
    note(level, concat(label, "byte[" + len + "]: "));
    byte[] octets = readExactBytes(len);
    writeLine(level + 1, readResetBuffer(), false, "oid: " + new Asn1Oid(octets).getId());
  }

  private void dumpPublicKey(int level, String label, int keyAlg) throws CodecException {
    if (keyAlg == ConstPublicKeyAlgorithm.rsaEncryption) {
      if (peekType().isByteString()) {
        printByteString(level, concat(label, "modulus"));
      } else {
        printAndReadArrayLen(level, label);
        printByteString(level + 1, "[0]. modulus");
        printByteString(level + 1, "[1]. exponent");
      }
      return;
    }

    boolean point = keyAlg == ConstPublicKeyAlgorithm.ed25519
        || keyAlg == ConstPublicKeyAlgorithm.ed448
        || keyAlg == ConstPublicKeyAlgorithm.x25519
        || keyAlg == ConstPublicKeyAlgorithm.x448
        || ConstPublicKeyAlgorithm.isWeierstrass(keyAlg);
    output(level, point ? concat(label, "EC point") : label);
  }

  private void dumpSignature(int level, String label, int sigAlg) throws CodecException {
    if (!ConstSignatureAlgorithm.isStaticDhSignature(sigAlg)) {
      output(level, label);
    } else if (peekType().isByteString()) {
      printByteString(level, concat(label, "DhSigStatic.hashValue"));
    } else {
      printAndReadArrayLen(level, concat(label, "DhSigStatic"));
      dumpName(level + 1, "[0]. issuer");
      printByteString(level + 1, "[1]. certificateSerialNumber");
      printByteString(level + 1, "[2]. hashValue");
    }
  }

  private void dumpName(int level, String label) throws CodecException {
    if (!peekType().isArray()) {
      dumpRdnValue(level, label);
      return;
    }
    int n = printAndReadEntryLen(level, label, 2, "attribute");
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "attribute[" + i + "]");
      if (peekType().isByteString()) {
        dumpOid(level + 1, c.label("type"));
      } else {
        dumpCode(level + 1, ConstRegistry.RDN_ATTRIBUTE::nameOf, c.label("type"),
            ", PrintableString");
      }
      dumpRdnValue(level + 1, c.label("value"));
    }
  }

  private void dumpNameVariant(int level, String label) throws CodecException {
    printAndReadArrayLen(level, label);
    int type = readInt();
    note(level + 1, "[0]. type=" + ConstCertificateType.describe(type));
    if (type == ConstCertificateType.x509) {
      printByteString(level + 1, "[1]. value: DER-encoded Name");
    } else if (type == ConstCertificateType.c509) {
      dumpName(level + 1, "[1]. value");
    } else {
      output(level + 1, "[1]. value");
    }
  }


  private void dumpRdnValue(int level, String label) throws CodecException {
    CborType type = peekType();
    if (type.isTextString()) {
      printTextString(level, label);
    } else if (type.isByteString()) {
      printByteString(level, label);
    } else if (type.isTag()) {
      note(level, label + "=tag(" + readTag() + ")");
      printByteString(level + 1, "");
    } else if (type.isNull()) {
      printNull(level, label);
    } else if (type.isUndefined()) {
      readUndefined();
      note(level, label + "=<undefined>");
    } else {
      throw new CodecException("unexpected CBOR type of " + label + ": " + type);
    }
  }

  private void dumpNameTemplate(int level, String label) throws CodecException {
    int n = printAndReadEntryLen(level, label, 4, "attribute");
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "attribute[" + i + "]");
      dumpCode(level + 1, ConstRegistry.RDN_ATTRIBUTE::nameOf, "[0]. type", "");
      note(level + 1, "[1]. minOccurs=" + readInt());
      note(level + 1, "[2]. maxOccurs=" + readInt());
      dumpRdnValue(level + 1, "[3]. value");
    }
  }

  // ----- extensions and attributes -----

  private void dumpExtensions(int level, String label) throws CodecException {
    CborType type = peekType();
    if (type.isInt()) {
      int v = readInt();
      note(level, label + "=" + v + ", KeyUsage" + (v < 0 ? ", critical: " : ": ")
          + new C509KeyUsage(Math.abs(v)).names());
      return;
    }
    if (!type.isArray()) {
      throw new CodecException("unexpected CBOR type of " + label + ": " + type);
    }
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "extension[" + i + "]");
      long id = dumpCode(level + 1, ConstExtensionId::name, c.label("id"), ", critical");
      dumpExtensionValue(level + 1, Math.abs(id), c.label("value"));
    }
  }

  private void dumpExtensionTemplates(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 3;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "extension[" + i + "]");
      long id = dumpCode(level + 1, ConstExtensionId::name, c.label("id"), "");
      note(level + 1, c.label(readBoolean() ? "optional" : "required"));
      long absId = Math.abs(id);
      optional(level + 1, c.label("value"), (l, valueLabel) ->
          dumpExtensionValue(l, absId, valueLabel));
    }
  }

  private void dumpExtensionValue(int level, long id, String label) throws CodecException {
    ValueDumper dumper = extensionDumpers.get(id);
    if (dumper == null) {
      output(level, label);
    } else {
      dumper.dump(level, label);
    }
  }

  private void dumpAttributes(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "attribute[" + i + "]");
      long type = dumpCode(level + 1, ConstAttributeType::name, c.label("type"), "");
      ValueDumper dumper = attributeDumpers.get(type);
      String valueLabel = c.label("value");
      if (dumper == null) {
        output(level + 1, valueLabel);
      } else {
        dumper.dump(level + 1, valueLabel);
      }
    }
  }

  private void dumpChallengePassword(int level, String label) throws CodecException {
    if (!peekType().isTag()) {
      printTextString(level, label);
      return;
    }
    long tag = readTag();
    note(level, label + ": tag=" + tag + (tag == 121 ? ", PrintableString" : ""));
    printTextString(level + 1, "");
  }

  private void dumpPossession(int level, String label) throws CodecException {
    int len = printAndReadArrayLen(level, label);
    if (len != 3) {
      throw new CodecException("private key possession statement: array length " + len);
    }
    dumpName(level + 1, "[0]. issuer");
    printByteString(level + 1, "[1]. certificateSerialNumber");
    printByteStringObj(level + 1, "[2]. cert");
  }

  private void dumpChangeSubjectName(int level, String label) throws CodecException {
    int len = printAndReadArrayLen(level, label);
    if (len != 2) {
      throw new CodecException("change subject name: array length " + len);
    }
    if (peekType().isNull()) {
      printNull(level + 1, "[0]. subject");
    } else {
      dumpName(level + 1, "[0]. subject");
    }

    if (peekType().isNull()) {
      printNull(level + 1, "[1]. subjectAlt");
    } else {
      dumpAltName(level + 1, "[1]. subjectAlt");
    }
  }

  private void dumpKeyUsage(int level, String label) throws CodecException {
    int v = readInt();
    note(level, label + "=" + v + ": " + new C509KeyUsage(v).names());
  }

  private void dumpBasicConstraints(int level, String label) throws CodecException {
    int v = readInt();
    note(level, label + "=" + v + ": " + (v == -2 ? "end entity"
        : "CA, path length: " + (v == -1 ? "unlimited" : Integer.toString(v))));
  }

  private void dumpAltName(int level, String label) throws CodecException {
    if (peekType().isTextString()) {
      printTextString(level, label + ": DNS");
    } else {
      dumpGeneralNames(level, label);
    }
  }

  private void dumpGeneralNames(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "GeneralName[" + i + "]");
      int tag = readInt();
      note(level + 1, c.label("tag=" + tag + ": " + ConstGeneralNameTag.name(tag)));
      String valueLabel = c.label("value");
      switch (tag) {
        case ConstGeneralNameTag.otherName:
        case ConstGeneralNameTag.hardwareModuleName:
          printAndReadArrayLen(level + 1, valueLabel);
          dumpOid(level + 2, "[0]. type");
          printByteString(level + 2, "[1]. value");
          break;
        case ConstGeneralNameTag.directoryName:
          dumpName(level + 1, valueLabel);
          break;
        case ConstGeneralNameTag.registeredID:
          dumpOid(level + 1, valueLabel);
          break;
        default:
          output(level + 1, valueLabel);
      }
    }
  }

  private void dumpNullableGeneralNames(int level, String label) throws CodecException {
    if (peekType().isNull()) {
      printNull(level, label);
    } else {
      dumpGeneralNames(level, label);
    }
  }

  private void dumpAuthorityKeyId(int level, String label) throws CodecException {
    if (peekType().isByteString()) {
      printByteString(level, label + ": keyIdentifier");
      return;
    }
    printAndReadArrayLen(level, label);
    printByteStringObj(level + 1, "[0]. keyIdentifier");
    dumpGeneralNames(level + 1, "[1]. authorityCertIssuer");
    printByteString(level + 1, "[2]. authorityCertSerialNumber");
  }

  private void dumpExtKeyUsage(int level, String label) throws CodecException {
    if (!peekType().isArray()) {
      dumpCode(level, ConstExtendedKeyUsage::name, label, "");
      return;
    }
    int n = printAndReadArrayLen(level, label);
    for (int i = 0; i < n; i++) {
      dumpCode(level + 1, ConstExtendedKeyUsage::name, "[" + i + "]. ", "");
    }
  }

  private void dumpInfoAccess(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "AccessDescription[" + i + "]");
      dumpCode(level + 1, intNamer(ConstAccessMethod::name), c.label("accessMethod"), "");
      printTextString(level + 1, c.label("uri"));
    }
  }

  private void dumpPolicies(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "PolicyInformation[" + i + "]");
      dumpCode(level + 1, ConstCertificatePolicy::name, c.label("policyIdentifier"), "");
      int q = printAndReadArrayLen(level + 1, c.label("policyQualifiers")) / 2;
      Counter qc = new Counter();
      for (int j = 0; j < q; j++) {
        printNoContentLine(level + 2, "PolicyQualifierInfo[" + j + "]");
        dumpCode(level + 2, intNamer(ConstPolicyQualifier::name), qc.label("policyQualifierId"), "");
        printTextString(level + 2, qc.label("qualifier"));
      }
    }
  }

  private void dumpPolicyMappings(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "PolicyMapping[" + i + "]");
      dumpCode(level + 1, ConstCertificatePolicy::name, c.label("issuerDomainPolicy"), "");
      dumpCode(level + 1, ConstCertificatePolicy::name, c.label("subjectDomainPolicy"), "");
    }
  }

  private void dumpPolicyConstraints(int level, String label) throws CodecException {
    printAndReadArrayLen(level, label);
    printLongObj(level + 1, "[0]. requireExplicitPolicy");
    printLongObj(level + 1, "[1]. inhibitPolicyMapping");
  }

  private void dumpNameConstraints(int level, String label) throws CodecException {
    printAndReadArrayLen(level, label);
    dumpNullableGeneralNames(level + 1, "[0]. permittedSubtrees");
    dumpNullableGeneralNames(level + 1, "[1]. excludedSubtrees");
  }

  private void dumpDistPoints(int level, String label) throws CodecException {
    if (peekType().isTextString()) {
      printTextString(level, label + ": fullName");
      return;
    }
    int n = printAndReadArrayLen(level, label);
    for (int i = 0; i < n; i++) {
      printAndReadArrayLen(level + 1, "DistributionPoint[" + i + "]");
      if (peekType().isTextString()) {
        printTextString(level + 2, "[0]. fullName");
      } else {
        int uris = printAndReadArrayLen(level + 2, "[0]. fullName");
        for (int j = 0; j < uris; j++) {
          printTextString(level + 3, "[" + j + "]");
        }
      }
      if (peekType().isNull()) {
        printNull(level + 2, "[1]. reasons");
      } else {
        int v = readInt();
        note(level + 2, "[1]. reasons=" + v + ": " + new C509ReasonFlags(v).names());
      }
      if (peekType().isNull()) {
        printNull(level + 2, "[2]. cRLIssuer");
      } else {
        dumpName(level + 2, "[2]. cRLIssuer");
      }
    }
  }

  private void dumpTlsFeatures(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label);
    for (int i = 0; i < n; i++) {
      int v = readInt();
      String name = C509TLSFeatures.nameOf(v);
      note(level + 1, "[" + i + "]. " + (name == null ? "unknown" : name) + " (" + v + ")");
    }
  }

  private void dumpAsIdentifiers(int level, String label) throws CodecException {
    if (peekType().isNull()) {
      printNull(level, label + ": inherit");
      return;
    }
    int n = printAndReadArrayLen(level, label);
    for (int i = 0; i < n; i++) {
      if (peekType().isInt()) {
        printLong(level + 1, "[" + i + "]. id (delta)");
      } else {
        printAndReadArrayLen(level + 1, "[" + i + "]. range");
        printLong(level + 2, "[0]. min (delta)");
        printLong(level + 2, "[1]. max - min");
      }
    }
  }

  private void dumpIpAddrBlocks(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label);
    if (n % 3 != 0) {
      throw new CodecException("IPAddrBlocks: array length " + n + " is not a multiple of 3");
    }
    Counter c = new Counter();
    for (int i = 0; i < n / 3; i++) {
      printNoContentLine(level + 1, "IPAddressFamily[" + i + "]");
      int afi = readInt();
      note(level + 1, c.label("AFI=" + afi + ": " + C509IPAddressFamily.afiName(afi)));
      String safiLabel = c.label("SAFI");
      if (peekType().isNull()) {
        printNull(level + 1, safiLabel);
      } else {
        int safi = readInt();
        note(level + 1, safiLabel + "=" + safi + ": " + C509IPAddressFamily.safiName(safi));
      }

      String choiceLabel = c.label("addresses");
      if (peekType().isNull()) {
        printNull(level + 1, choiceLabel + ": inherit");
        continue;
      }
      int m = printAndReadArrayLen(level + 1, choiceLabel);
      for (int j = 0; j < m; j++) {
        CborType type = peekType();
        if (type.isInt()) {
          printLong(level + 2, "[" + j + "]. prefix");
        } else if (type.isByteString()) {
          printByteString(level + 2, "[" + j + "]. prefix");
        } else {
          printAndReadArrayLen(level + 2, "[" + j + "]. range");
          boolean ints = peekType().isInt();
          for (String end : new String[] {"[0]. min", "[1]. max"}) {
            if (ints) {
              printLong(level + 3, end);
            } else {
              printByteString(level + 3, end);
            }
          }
        }
      }
    }
  }

  private void dumpPreferredSigAlgs(int level, String label) throws CodecException {
    int n = printAndReadArrayLen(level, label) / 2;
    Counter c = new Counter();
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "PreferredSignatureAlgorithm[" + i + "]");
      dumpAlgorithm(level + 1, ConstRegistry.SIGNATURE_ALGORITHM, c.label("sigIdentifier"));
      String keysLabel = c.label("pubKeyAlgIdentifiers");
      CborType type = peekType();
      if (type.isNull()) {
        printNull(level + 1, keysLabel);
      } else if (type.isInt()) {
        dumpAlgorithm(level + 1, ConstRegistry.PUBLIC_KEY_ALGORITHM, keysLabel);
      } else {
        dumpAlgorithmList(level + 1, ConstRegistry.PUBLIC_KEY_ALGORITHM, keysLabel);
      }
    }
  }

  // ----- CRL -----

  private void dumpRevocationGroup(int level, int index) throws CodecException {
    printNoContentLine(level, "PerIssuerRevokedCerts[" + index + "]");
    Counter c = new Counter();
    String issuerLabel = c.label("issuer");
    if (peekType().isNull()) {
      printNull(level, issuerLabel);
    } else {
      dumpNameVariant(level, issuerLabel);
    }

    String layoutLabel = c.label("revokedCertsControl");
    int serialLen = 0;
    int dateLen = 0;
    boolean reasons = false;
    Instant base = null;
    if (peekType().isNull()) {
      printNull(level, layoutLabel);
    } else {
      printAndReadArrayLen(level, layoutLabel);
      Counter lc = new Counter();
      long flags = readLong();
      reasons = (flags & 2) != 0;
      note(level + 1, lc.label("flags: " + C509RevokedCertsControl.flagsText(flags)));
      serialLen = (int) printLong(level + 1, lc.label("serialNumberLength"));
      dateLen = (int) printLong(level + 1, lc.label("dateLength"));
      Long t = dumpTime(level + 1, lc.label("baseDate"));
      base = t == null ? null : Instant.ofEpochSecond(t);
    }

    dumpExtensions(level, c.label("extensions"));
    dumpEntries(level, c.label("revokedCerts"), serialLen, dateLen, reasons, base);
    dumpEntries(level, c.label("removedFromCRLCerts"), serialLen, dateLen, false, base);
  }

  private void dumpEntries(
      int level, String label, int serialLen, int dateLen,
      boolean reasons, Instant base) throws CodecException {
    if (peekType().isNull()) {
      printNull(level, label);
      return;
    }
    int size = serialLen + dateLen + (reasons ? 1 : 0);
    int total = readByteStringLength();
    if (size == 0 || total % size != 0) {
      throw new CodecException(label + ": length " + total + " does not fit entry size "
          + size);
    }
    int n = total / size;
    note(level, label + "=byte[" + total + "], " + n + " entries");
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, "entry[" + i + "]");
      byte[] serial = readExactBytes(serialLen);
      writeLine(level + 1, readResetBuffer(), false, "serial=" + Hex.encodeUpper(serial));
      if (dateLen > 0) {
        byte[] date = readExactBytes(dateLen);
        writeLine(level + 1, readResetBuffer(), false, "date=" + Hex.encodeUpper(date) + ": "
            + base.plusSeconds(new BigInteger(1, date).longValueExact()));
      }
      if (reasons) {
        int reason = readExactBytes(1)[0] & 0xFF;
        writeLine(level + 1, readResetBuffer(), false,
            "reason=" + reason + ": " + C509RevocationReason.nameOf(reason));
      }
    }
  }

  // ----- OCSP -----

  /**
   * Dumps PerIssuerOCSPRequests or PerIssuerOCSPResponses.
   */
  private void dumpIssuerGroups(int level, String label, String groupName, long producedAt)
      throws CodecException {
    boolean responses = groupName.endsWith("Response");
    int n = printAndReadArrayLen(level, label) / 3;
    for (int i = 0; i < n; i++) {
      printNoContentLine(level + 1, groupName + "[" + i + "]");
      Counter c = new Counter();
      printByteString(level + 1, c.label("issuerCertHash"));
      dumpExtensions(level + 1, c.label("extensions"));
      int width = responses ? 5 : 2;
      int m = printAndReadArrayLen(level + 1, c.label(responses ? "answers" : "queries")) / width;
      for (int j = 0; j < m; j++) {
        printNoContentLine(level + 2, (responses ? "SingleCertResponse[" : "SingleCertRequest[")
            + j + "]");
        Counter sc = new Counter();
        printByteString(level + 2, sc.label("serialNumberHash"));
        if (responses) {
          dumpCertStatus(level + 2, sc.label("certStatus"));
          dumpRelativeTime(level + 2, sc.label("thisUpdate"), producedAt);
          dumpRelativeTime(level + 2, sc.label("nextUpdate"), producedAt);
        }
        dumpExtensions(level + 2, sc.label("extensions"));
      }
    }
  }

  private void dumpCertStatus(int level, String label) throws CodecException {
    if (peekType().isInt()) {
      int code = readInt();
      note(level, label + "=" + C509CertStatus.Kind.ofCode(code).text() + " (" + code + ")");
      return;
    }
    printAndReadArrayLen(level, label + ": revoked");
    dumpTime(level + 1, "[0]. revocationTime");
    int reason = readInt();
    note(level + 1, "[1]. revocationReason=" + C509RevocationReason.nameOf(reason)
        + " (" + reason + ")");
  }

  private void dumpCertChain(int level, String label) throws CodecException {
    CborType type = peekType();
    if (type.isNull()) {
      printNull(level, label);
      return;
    }

    // CertChainVariant = [type, chain]
    printAndReadArrayLen(level++, label + ": CertChainVariant");
    int certType = readInt();
    String chainLabel;
    String entry;
    switch (certType) {
      case ConstCertificateType.x509:
        chainLabel = "[1]. chain (COSE_X509)";
        entry = "X509Certificate";
        break;
      case ConstCertificateType.c509:
        chainLabel = "[1]. chain (COSE_C509)";
        entry = "C509Certificate";
        break;
      default:
        chainLabel = "[1]. chain";
        entry = null;
    }
    note(level, "[0]. type=" + ConstCertificateType.describe(certType));

    if (entry == null) {
      output(level, chainLabel);
    } else if (peekType().isByteString()) {
      printByteString(level, chainLabel);
    } else {
      int n = printAndReadArrayLen(level, chainLabel);
      for (int i = 0; i < n; i++) {
        printByteString(level + 1, "[" + i + "]. " + entry);
      }
    }
  }

}
