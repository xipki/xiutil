// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.name;

import org.xipki.c509.base.C509Cbor;
import org.xipki.c509.base.C509CborItem;
import org.xipki.c509.base.C509ObjectId;
import org.xipki.c509.base.C509OtherName;
import org.xipki.c509.base.C509TextTree;
import org.xipki.c509.registry.ConstGeneralNameTag;
import org.xipki.codec.Hex;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncodedItem;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;
import org.xipki.codec.util.Args;
import org.xipki.codec.util.IPAddressUtil;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One entry of a GeneralNames sequence (draft-ietf-cose-cbor-encoded-cert-21, Section 3.3).
 *
 * <pre>
 * GeneralName = ( GeneralNameType : int, GeneralNameValue : any )
 * GeneralNames = [ + GeneralName ]
 * </pre>
 * <p>
 * Instances are created by the static factories; the concrete shape of the value depends on
 * the tag (see {@link ConstGeneralNameTag}). The value of a tag registered with
 * {@link #register} is decoded into its registered class, see {@link #custom()}; the value of
 * any other tag without a dedicated shape is kept as {@link CborEncodedItem}.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class C509GeneralName extends C509CborItem {

  private static final class Binding {

    private final Class<? extends C509CborItem> type;

    private final C509Cbor.Reader<? extends C509CborItem> reader;

    private Binding(Class<? extends C509CborItem> type,
                    C509Cbor.Reader<? extends C509CborItem> reader) {
      this.type = type;
      this.reader = reader;
    }

  }

  // concurrent: tags may be registered at runtime while other threads read
  private static final Map<Integer, Binding> CUSTOM_TAGS = new ConcurrentHashMap<>();

  private final int tag;

  private C509GeneralName(int tag) {
    this.tag = tag;
  }

  public final int tag() {
    return tag;
  }

  /** The value of a text-valued name (DNS, URI, RFC 822, SMTP UTF-8), otherwise null. */
  public String text() {
    return null;
  }

  /** The value of an octet-valued name (IP address, MAC address), otherwise null. */
  public byte[] octets() {
    return null;
  }

  /** The value of a directory name, otherwise null. */
  public C509Name directoryName() {
    return null;
  }

  /** The value of a registered ID, otherwise null. */
  public C509ObjectId registeredId() {
    return null;
  }

  /** The value of an otherName or a hardwareModuleName, otherwise null. */
  public C509OtherName otherName() {
    return null;
  }

  /** The value of a tag without a dedicated shape and not registered, otherwise null. */
  public CborEncodedItem raw() {
    return null;
  }

  /** The value of a tag registered with {@link #register}, otherwise null. */
  public C509CborItem custom() {
    return null;
  }

  /**
   * The value of a tag registered with {@link #register}, cast to the registered class.
   *
   * @throws ClassCastException if the value is not an instance of {@code clazz}.
   */
  public <T extends C509CborItem> T custom(Class<T> clazz) {
    return clazz.cast(custom());
  }

  protected abstract void writeValue(CborEncoder out) throws CodecException;

  @Override
  protected final void writeTo(CborEncoder out) throws CodecException {
    out.writeLong(tag);
    writeValue(out);
  }

  // ----- factories -----

  public static C509GeneralName dns(String name) {
    return new Text(ConstGeneralNameTag.dNSName, "DNS", name);
  }

  public static C509GeneralName uri(String uri) {
    return new Text(ConstGeneralNameTag.uniformResourceIdentifier, "URI", uri);
  }

  public static C509GeneralName rfc822(String address) {
    return new Text(ConstGeneralNameTag.rfc822Name, "RFC822", address);
  }

  public static C509GeneralName smtpUtf8Mailbox(String mailbox) {
    return new Text(ConstGeneralNameTag.SmtpUTF8Mailbox, "SMTP", mailbox);
  }

  public static C509GeneralName directory(C509Name name) {
    return new Directory(name);
  }

  public static C509GeneralName registeredId(C509ObjectId oid) {
    return new Registered(oid);
  }

  public static C509GeneralName otherName(C509OtherName value) {
    return new Other(ConstGeneralNameTag.otherName, "Other Name", value);
  }

  public static C509GeneralName hardwareModuleName(C509OtherName value) {
    return new Other(ConstGeneralNameTag.hardwareModuleName, "Hardware Module Name", value);
  }

  /**
   * IP address: 4 or 16 bytes; in name constraints additionally followed by one byte with the
   * prefix length (see {@link #ipSubnet(byte[])}).
   */
  public static C509GeneralName ip(byte[] address) {
    return new Octets(ConstGeneralNameTag.iPAddress, address);
  }

  public static C509GeneralName ip(String address) {
    return ip(IPAddressUtil.ipAddrToGeneralNameEncoding(address));
  }

  /**
   * Converts an X.509 name constraints subnet (address followed by mask, 8 or 32 bytes) into
   * the C509 form (address followed by the prefix length).
   */
  public static C509GeneralName ipSubnet(byte[] addressAndMask) {
    int len = addressAndMask.length;
    if (len != 8 && len != 32) {
      throw new IllegalArgumentException("invalid address-and-mask length " + len);
    }
    int half = len / 2;
    BigInteger mask = new BigInteger(1, Arrays.copyOfRange(addressAndMask, half, len));
    int bits = 8 * half;
    int prefixLen = (mask.signum() == 0) ? 0 : bits - mask.getLowestSetBit();
    byte[] value = Arrays.copyOf(addressAndMask, half + 1);
    value[half] = (byte) prefixLen;
    return ip(value);
  }

  public static C509GeneralName macAddress(byte[] address) {
    int len = address.length;
    if (len != 6 && len != 8) {
      throw new IllegalArgumentException("MAC address must have 6 or 8 bytes, not " + len);
    }
    return new Octets(ConstGeneralNameTag.MACAddress, address);
  }

  /**
   * Creates a general name of a tag without a dedicated shape. For a tag registered with
   * {@link #register}, the value is decoded into the registered class.
   *
   * @param tag   the tag, not one of those with a dedicated shape (e.g. DNS name).
   * @param value the value.
   * @throws IllegalArgumentException if the tag has a dedicated shape, or if the value does not
   *         fit the class registered for the tag.
   */
  public static C509GeneralName raw(int tag, CborEncodedItem value) {
    if (hasDedicatedShape(tag)) {
      throw new IllegalArgumentException("general name tag "
          + ConstGeneralNameTag.describe(tag) + " has a dedicated shape");
    }

    Binding b = CUSTOM_TAGS.get(tag);
    if (b == null) {
      return new Raw(tag, value);
    }
    return new Custom(tag, convert(tag, b, Args.notNull(value, "value").getEncoded()));
  }

  /**
   * Creates a general name of a tag registered with {@link #register}.
   *
   * @param tag   the registered tag.
   * @param value the value. A value of a foreign class is converted to the registered class,
   *              provided its encoding fits.
   * @throws IllegalArgumentException if the tag is not registered, or the value does not fit.
   */
  public static C509GeneralName of(int tag, C509CborItem value) {
    Binding b = CUSTOM_TAGS.get(tag);
    if (b == null) {
      throw new IllegalArgumentException("general name tag "
          + ConstGeneralNameTag.describe(tag) + " is not registered");
    }

    Args.notNull(value, "value");
    return new Custom(tag,
        b.type.isInstance(value) ? value : convert(tag, b, value.getEncoded()));
  }

  private static C509CborItem convert(int tag, Binding b, byte[] encoded) {
    try {
      return C509Cbor.parse(encoded, b.reader);
    } catch (CodecException | RuntimeException e) {
      throw new IllegalArgumentException("general name tag " + ConstGeneralNameTag.describe(tag)
          + " does not accept the value", e);
    }
  }

  /**
   * Registers the value class of general name tags not known to this library, so that they are
   * decoded into {@code clazz} instead of being kept as {@link CborEncodedItem}. Register before
   * the first general name with these tags is decoded or created, e.g. at application start-up.
   * To give the tags a name, use {@link ConstGeneralNameTag#register(int, String)}.
   *
   * @param <T>    the value class.
   * @param clazz  the value class.
   * @param reader reads the value from the CBOR stream, usually {@code MyValue::read}.
   * @param tags   the general name tags.
   * @throws IllegalArgumentException if one of the tags has a dedicated shape (e.g. DNS name).
   * @throws IllegalStateException if one of the tags is already registered. In both cases none
   *         of the tags is registered.
   */
  public static synchronized <T extends C509CborItem> void register(
      Class<T> clazz, C509Cbor.Reader<T> reader, int... tags) {
    Args.notNull(clazz, "clazz");
    Args.notNull(reader, "reader");
    if (tags == null || tags.length == 0) {
      throw new IllegalArgumentException("tags must not be empty");
    }

    for (int tag : tags) {
      if (hasDedicatedShape(tag)) {
        throw new IllegalArgumentException("general name tag "
            + ConstGeneralNameTag.describe(tag) + " has a dedicated shape");
      }
      if (CUSTOM_TAGS.containsKey(tag)) {
        throw new IllegalStateException("duplicate registration for general name tag "
            + ConstGeneralNameTag.describe(tag));
      }
    }

    Binding binding = new Binding(clazz, reader);
    for (int tag : tags) {
      CUSTOM_TAGS.put(tag, binding);
    }
  }

  private static boolean hasDedicatedShape(int tag) {
    switch (tag) {
      case ConstGeneralNameTag.dNSName:
      case ConstGeneralNameTag.uniformResourceIdentifier:
      case ConstGeneralNameTag.rfc822Name:
      case ConstGeneralNameTag.SmtpUTF8Mailbox:
      case ConstGeneralNameTag.directoryName:
      case ConstGeneralNameTag.registeredID:
      case ConstGeneralNameTag.otherName:
      case ConstGeneralNameTag.hardwareModuleName:
      case ConstGeneralNameTag.iPAddress:
      case ConstGeneralNameTag.MACAddress:
        return true;
      default:
        return false;
    }
  }

  public static C509GeneralName read(CborDecoder in) throws CodecException {
    int tag = in.readInt();
    switch (tag) {
      case ConstGeneralNameTag.dNSName:
        return dns(in.readTextString());
      case ConstGeneralNameTag.uniformResourceIdentifier:
        return uri(in.readTextString());
      case ConstGeneralNameTag.rfc822Name:
        return rfc822(in.readTextString());
      case ConstGeneralNameTag.SmtpUTF8Mailbox:
        return smtpUtf8Mailbox(in.readTextString());
      case ConstGeneralNameTag.directoryName:
        return directory(C509Name.read(in));
      case ConstGeneralNameTag.registeredID:
        return registeredId(C509ObjectId.read(in));
      case ConstGeneralNameTag.otherName:
        return otherName(C509OtherName.read(in));
      case ConstGeneralNameTag.hardwareModuleName:
        return hardwareModuleName(C509OtherName.read(in));
      case ConstGeneralNameTag.iPAddress:
        return ip(in.readByteString());
      case ConstGeneralNameTag.MACAddress:
        return macAddress(in.readByteString());
      default:
        Binding b = CUSTOM_TAGS.get(tag);
        return (b == null) ? new Raw(tag, in.readEncodedItem())
            : new Custom(tag, b.reader.read(in));
    }
  }

  // ----- shapes -----

  private static final class Text extends C509GeneralName {

    private final String label;

    private final String value;

    private Text(int tag, String label, String value) {
      super(tag);
      this.label = label;
      this.value = Args.notNull(value, "value");
    }

    @Override
    public String text() {
      return value;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      out.writeTextString(value);
    }

    @Override
    protected void render(C509TextTree out) {
      out.kv(label, value);
    }

  }

  private static final class Octets extends C509GeneralName {

    private final byte[] value;

    private Octets(int tag, byte[] value) {
      super(tag);
      this.value = Args.notNull(value, "value").clone();
    }

    @Override
    public byte[] octets() {
      return value.clone();
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      out.writeByteString(value);
    }

    @Override
    protected void render(C509TextTree out) {
      if (tag() == ConstGeneralNameTag.MACAddress) {
        out.kv("MAC Address", Hex.encodeUpper(value));
      } else {
        out.kv("IP Address", ipText(value) + " (0x" + Hex.encode(value) + ")");
      }
    }

    private static String ipText(byte[] b) {
      int len = b.length;
      StringBuilder sb = new StringBuilder();
      if (len == 4 || len == 5) {
        for (int i = 0; i < 4; i++) {
          sb.append(i == 0 ? "" : ".").append(b[i] & 0xFF);
        }
      } else if (len == 16 || len == 17) {
        for (int i = 0; i < 16; i += 2) {
          sb.append(i == 0 ? "" : ":").append(Hex.encodeUpper(b, i, 2));
        }
      } else {
        return "?";
      }
      if (len == 5 || len == 17) {
        sb.append('/').append(b[len - 1] & 0xFF);
      }
      return sb.toString();
    }

  }

  private static final class Directory extends C509GeneralName {

    private final C509Name name;

    private Directory(C509Name name) {
      super(ConstGeneralNameTag.directoryName);
      this.name = Args.notNull(name, "name");
    }

    @Override
    public C509Name directoryName() {
      return name;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      name.encode(out);
    }

    @Override
    protected void render(C509TextTree out) {
      out.kv("Directory Name", name.getNameText());
    }

  }

  private static final class Registered extends C509GeneralName {

    private final C509ObjectId oid;

    private Registered(C509ObjectId oid) {
      super(ConstGeneralNameTag.registeredID);
      this.oid = Args.notNull(oid, "oid");
    }

    @Override
    public C509ObjectId registeredId() {
      return oid;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      oid.encode(out);
    }

    @Override
    protected void render(C509TextTree out) {
      out.kv("Registered ID", oid);
    }

  }

  private static final class Other extends C509GeneralName {

    private final String label;

    private final C509OtherName value;

    private Other(int tag, String label, C509OtherName value) {
      super(tag);
      this.label = label;
      this.value = Args.notNull(value, "value");
    }

    @Override
    public C509OtherName otherName() {
      return value;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      value.encode(out);
    }

    @Override
    protected void render(C509TextTree out) {
      out.item(label, value);
    }

  }

  private static final class Custom extends C509GeneralName {

    private final C509CborItem value;

    private Custom(int tag, C509CborItem value) {
      super(tag);
      this.value = Args.notNull(value, "value");
    }

    @Override
    public C509CborItem custom() {
      return value;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      value.encode(out);
    }

    @Override
    protected void render(C509TextTree out) {
      out.item(ConstGeneralNameTag.describe(tag()), value);
    }

  }

  private static final class Raw extends C509GeneralName {

    private final CborEncodedItem value;

    private Raw(int tag, CborEncodedItem value) {
      super(tag);
      this.value = Args.notNull(value, "value");
    }

    @Override
    public CborEncodedItem raw() {
      return value;
    }

    @Override
    protected void writeValue(CborEncoder out) throws CodecException {
      value.encode(out);
    }

    @Override
    protected void render(C509TextTree out) {
      out.kv(ConstGeneralNameTag.describe(tag()), value.toDiagnostic());
    }

  }

}
