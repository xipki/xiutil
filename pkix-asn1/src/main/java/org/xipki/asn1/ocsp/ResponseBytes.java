// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.asn1.ocsp;

import org.xipki.codec.asn1.Asn1Encodable;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.asn1.Asn1Sequence;
import org.xipki.codec.asn1.oid.OcspOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseBytes ::= SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING }
 * </pre>
 *
 * @author Lijun Liao (xipki)
 */
public class ResponseBytes extends Asn1Encodable {

  private final Asn1Oid responseType;
  private final Asn1OctetString response;

  private boolean parsed;
  private BasicOCSPResponse basicOCSPResponse;

  private ResponseBytes(Asn1Oid responseType, Asn1OctetString response) {
    this.responseType = Args.notNull(responseType, "responseType");
    this.response = Args.notNull(response, "response");
  }

  public static ResponseBytes fromAsn1(Asn1Sequence seq) throws CodecException {
    Args.sequenceSizeEquals(seq, "seq", 2);
    Asn1Oid responseType = seq.getOidAt(0);
    Asn1OctetString response = seq.getOctetStringAt(1);
    ResponseBytes r = new ResponseBytes(responseType, response);
    r.parseValue();
    return r;
  }

  public static ResponseBytes createNoParse(Asn1Oid responseType, Asn1Encodable value) {
    return new ResponseBytes(responseType, new Asn1OctetString(value.getEncoded(Asn1Encoding.DER)));
  }

  public static ResponseBytes create(Asn1Oid responseType, Asn1Encodable value)
      throws CodecException {
    ResponseBytes r = createNoParse(responseType, value);
    r.parseValue();
    return r;
  }

  private static ResponseBytes create2(Asn1Oid responseType, Asn1Encodable value) {
    ResponseBytes r = createNoParse(responseType, value);
    r.parsed = true;
    return r;
  }

  public static ResponseBytes ofBasicResponse(BasicOCSPResponse basicOCSPResponse) {
    ResponseBytes r = create2(OcspOIDs.id_pkix_ocsp_basic, basicOCSPResponse);
    r.basicOCSPResponse = basicOCSPResponse;
    return r;
  }

  public Asn1Oid getResponseType() {
    return responseType;
  }

  public Asn1OctetString getResponse() {
    return response;
  }

  public byte[] response() {
    return response.getOctets();
  }

  public BasicOCSPResponse getBasicOCSPResponse() {
    return basicOCSPResponse;
  }

  @Override
  public Asn1Primitive toAsn1Primitive() {
    return new Asn1Sequence(responseType, response);
  }

  @Override
  public StringBuilder toString(StringBuilder buf, int indentLevel) {
    responseType.toStringNoLineSep(buf, indentLevel, "responseType", true);
    // print the parsed response only if it has already been parsed.
    return (basicOCSPResponse != null)
        ? basicOCSPResponse.toStringWithLineSep(buf, indentLevel, "response")
        : response.toStringWithLineSep(buf, indentLevel, "response");
  }

  private void parseValue() throws CodecException {
    if (parsed) {
      return;
    }

    if (OcspOIDs.id_pkix_ocsp_basic.equals(responseType)) {
      basicOCSPResponse = BasicOCSPResponse.fromEncoded(response.getOctets());
    }

    parsed = true;
  }
}
