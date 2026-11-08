// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ccc;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * CCC InstanceCACertificateExtensionSchema.
 * <pre>
 * SBxDKisCertificateExtensionSchema ::= SEQUENCE {
 *     key_server_provider_identifier UTF8String (SIZE (1..32)),
 *     service_provider_identifier    UTF8String (SIZE (1..32)),
 *     service_identifier             UTF8String (SIZE (1..32))
 * }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class SBxDKisCertificateExtensionSchema extends Asn1Encodable {

  private final Asn1OctetString keyServerProviderIdentifier;

  private final Asn1OctetString serviceProvideIdentifier;

  private final Asn1OctetString serviceIdentifier;

  public SBxDKisCertificateExtensionSchema(
      byte[] keyServerProviderIdentifier, byte[] serviceProvideIdentifier,
      byte[] serviceIdentifier) {
    Args.variableLen(keyServerProviderIdentifier, "keyServerProviderIdentifier", 1, 32);
    Args.variableLen(serviceProvideIdentifier, "serviceProvideIdentifier", 1, 32);
    Args.variableLen(serviceIdentifier, "serviceIdentifier", 1, 32);

    this.keyServerProviderIdentifier = new Asn1OctetString(keyServerProviderIdentifier);
    this.serviceProvideIdentifier = new Asn1OctetString(serviceProvideIdentifier);
    this.serviceIdentifier = new Asn1OctetString(serviceIdentifier);
  }

  private SBxDKisCertificateExtensionSchema(
      Asn1OctetString keyServerProviderIdentifier, Asn1OctetString serviceProvideIdentifier,
      Asn1OctetString serviceIdentifier) {
    this.keyServerProviderIdentifier = Args.variableLen(keyServerProviderIdentifier,
        "keyServerProviderIdentifier", 1, 32);
    this.serviceProvideIdentifier = Args.variableLen(serviceProvideIdentifier,
        "serviceProvideIdentifier", 1, 32);
    this.serviceIdentifier = Args.variableLen(serviceIdentifier,
        "serviceIdentifier", 1, 32);
  }

  public Asn1OctetString getKeyServerProviderIdentifier() {
    return keyServerProviderIdentifier;
  }

  public Asn1OctetString getServiceProvideIdentifier() {
    return serviceProvideIdentifier;
  }

  public Asn1OctetString getServiceIdentifier() {
    return serviceIdentifier;
  }

  public byte[] keyServerProviderIdentifier() {
    return keyServerProviderIdentifier.getOctets();
  }

  public byte[] serviceProvideIdentifier() {
    return serviceProvideIdentifier.getOctets();
  }

  public byte[] serviceIdentifier() {
    return serviceIdentifier.getOctets();
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(keyServerProviderIdentifier,
        serviceProvideIdentifier, serviceIdentifier);
  }

  public static SBxDKisCertificateExtensionSchema fromEncoded(byte[] encoded)
      throws CodecException {
    return fromAsn1(Asn1Sequence.fromEncoded(encoded));
  }

  public static SBxDKisCertificateExtensionSchema fromAsn1(Asn1Sequence seq)
      throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 3);
    Asn1OctetString keyServerProviderIdentifier = seq.getOctetStringAt(0);
    Asn1OctetString serviceProvideIdentifier = seq.getOctetStringAt(1);
    Asn1OctetString serviceIdentifier = seq.getOctetStringAt(2);
    return new SBxDKisCertificateExtensionSchema(keyServerProviderIdentifier,
          serviceProvideIdentifier, serviceIdentifier);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    keyServerProviderIdentifier.toStringWithLineSep(buf, indentLevel,
        "key_server_provider_identifier", true);
    serviceProvideIdentifier.toStringWithLineSep(buf, indentLevel,
        "service_provider_identifier", true);
    serviceIdentifier.toStringWithLineSep(buf, indentLevel, "service_identifier", true);
    return deleteLastNewLine(buf);
  }
}
