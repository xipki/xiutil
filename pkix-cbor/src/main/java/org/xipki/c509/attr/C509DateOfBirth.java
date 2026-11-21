// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.c509.attr;

import org.xipki.c509.base.C509TextTree;
import org.xipki.codec.cbor.CborDecoder;
import org.xipki.codec.cbor.CborEncoder;
import org.xipki.codec.exception.CodecException;

import java.time.LocalDate;

/**
 * The date of birth attribute, encoded as days since 1970-01-01.
 *
 * @author Lijun Liao (xipki)
 */
public final class C509DateOfBirth extends C509AttrValue {

  private final int epochDay;

  public C509DateOfBirth(int epochDay) {
    this.epochDay = epochDay;
  }

  /**
   * @param year: the year (usually 4 digit)
   * @param month: 1-12
   * @param day: 1-31
   */
  public C509DateOfBirth(int year, int month, int day) {
    this.epochDay = Math.toIntExact(LocalDate.of(year, month, day).toEpochDay());
  }

  public static C509DateOfBirth of(LocalDate date) {
    return new C509DateOfBirth(Math.toIntExact(date.toEpochDay()));
  }

  public int epochDay() {
    return epochDay;
  }

  public LocalDate date() {
    return LocalDate.ofEpochDay(epochDay);
  }

  public static C509DateOfBirth read(CborDecoder in) throws CodecException {
    return new C509DateOfBirth(in.readInt());
  }

  @Override
  protected void writeTo(CborEncoder out) throws CodecException {
    out.writeInt(epochDay);
  }

  @Override
  protected void render(C509TextTree out) {
    out.line(date().toString());
  }

  @Override
  public String label() {
    return "Date of Birth";
  }

}
