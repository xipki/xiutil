// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.util.http;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests for {@link HttpStatusCode#describe(int)}.
 *
 * @author Lijun Liao (xipki)
 */
public class HttpStatusCodeTest {

  @Test
  public void testDescribeKnownCode() {
    Assert.assertEquals("400 (Bad Request)",
        HttpStatusCode.describe(HttpStatusCode.SC_BAD_REQUEST));
    Assert.assertEquals("200 (OK)", HttpStatusCode.describe(HttpStatusCode.SC_OK));
    Assert.assertEquals("503 (Service Unavailable)",
        HttpStatusCode.describe(HttpStatusCode.SC_SERVICE_UNAVAILABLE));
  }

  @Test
  public void testDescribeUnknownCode() {
    Assert.assertEquals("599", HttpStatusCode.describe(599));
  }

  @Test
  public void testAllConstantsHaveReasonPhrase() throws Exception {
    for (java.lang.reflect.Field field : HttpStatusCode.class.getFields()) {
      if (field.getName().startsWith("SC_")) {
        int code = field.getInt(null);
        Assert.assertNotNull(field.getName(), HttpStatusCode.reasonPhrase(code));
      }
    }
  }

}
