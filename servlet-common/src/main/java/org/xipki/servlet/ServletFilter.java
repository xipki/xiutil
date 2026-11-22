// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.servlet;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.codec.util.Args;
import org.xipki.util.http.XiHttpFilter;
import org.xipki.util.http.XiHttpRequest;
import org.xipki.util.http.XiHttpResponse;
import org.xipki.util.password.Passwords;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Function;

/**
 * Servlet Filter.
 *
 * @author Lijun Liao (xipki)
 */
public abstract class ServletFilter implements Filter {

  private static final Logger LOG = LoggerFactory.getLogger(ServletFilter.class);

  /**
   * Name of the context parameter that specifies the base directory, against which relative
   * paths in the configuration are resolved. The default {@code xipki} is set in the web
   * application's {@code web.xml}. A relative value is resolved against the base directory of
   * the servlet container, see {@link #CONTAINER_BASE_PROPERTIES}. The value can be overridden
   * in the container, e.g. in Tomcat's {@code conf/context.xml} with
   * {@code <Parameter ... override="false"/>}.
   */
  public static final String PARAM_BASEDIR = "xipki.basedir";

  /**
   * System properties holding the base directory of the servlet container, in the order they
   * are tried: {@code catalina.base} (Tomcat, TomEE), {@code jetty.base} (Jetty),
   * {@code jboss.server.base.dir} (WildFly, JBoss EAP) and {@code com.sun.aas.instanceRoot}
   * (GlassFish, Payara).
   */
  static final List<String> CONTAINER_BASE_PROPERTIES = List.of(
      "catalina.base", "jetty.base", "jboss.server.base.dir", "com.sun.aas.instanceRoot");

  private XiHttpFilter filter0;

  /**
   * Creates the filter.
   * @param filterConfig the filter configuration.
   * @param basedir the base directory (absolute and canonical), against which relative paths
   *                in the configuration are resolved.
   * @return the filter.
   * @throws Exception if error occurs while creating the filter.
   */
  protected abstract XiHttpFilter initFilter(FilterConfig filterConfig, String basedir)
      throws Exception;

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    try {
      String basedir = getBasedir(filterConfig);
      Passwords.init(basedir);
      filter0 = initFilter(filterConfig, basedir);
    } catch (ServletException ex) {
      LOG.error("error initializing ServletFilter: {}", ex.getMessage());
      throw ex;
    } catch (Exception ex) {
      LOG.error("error initializing ServletFiler", ex);
      throw new ServletException(ex);
    }
  }

  private static String getBasedir(FilterConfig filterConfig) throws ServletException {
    return resolveBasedir(filterConfig.getServletContext().getInitParameter(PARAM_BASEDIR),
        System::getProperty);
  }

  /**
   * Resolves the value of the context parameter {@link #PARAM_BASEDIR}. A relative value is
   * resolved against the base directory of the servlet container, never against the working
   * directory.
   *
   * @param value the value of the context parameter.
   * @param systemProperties returns the value of a system property, or {@code null}.
   * @return the canonical path of the base directory.
   * @throws ServletException if the value is not set, contains an unresolved placeholder, is
   *         relative in an unknown servlet container, or is not an existing directory.
   */
  static String resolveBasedir(String value, Function<String, String> systemProperties)
      throws ServletException {
    if (value == null || value.isBlank()) {
      throw new ServletException("context parameter " + PARAM_BASEDIR + " is not set");
    }

    String str = value.trim();
    if (str.contains("${")) {
      // e.g. ${catalina.base}/xipki in a container that does not replace placeholders
      throw new ServletException("context parameter " + PARAM_BASEDIR
          + " contains an unresolved placeholder: " + str
          + "; use an absolute path, or a path relative to the container's base directory");
    }

    File dir = new File(str);
    if (!dir.isAbsolute()) {
      String containerBase = null;
      for (String name : CONTAINER_BASE_PROPERTIES) {
        String prop = systemProperties.apply(name);
        if (prop != null && !prop.isBlank()) {
          containerBase = prop.trim();
          break;
        }
      }

      if (containerBase == null) {
        throw new ServletException("context parameter " + PARAM_BASEDIR + " is relative ("
            + str + "), but the servlet container is unknown (none of the system properties "
            + String.join(", ", CONTAINER_BASE_PROPERTIES) + " is set); use an absolute path");
      }
      dir = new File(containerBase, str);
    }

    if (!dir.isDirectory()) {
      throw new ServletException("context parameter " + PARAM_BASEDIR
          + " is not an existing directory: " + dir.getPath());
    }

    String basedir;
    try {
      basedir = dir.getCanonicalPath();
    } catch (IOException ex) {
      basedir = dir.getAbsolutePath();
    }

    LOG.info("use basedir {}", basedir);
    return basedir;
  }

  @Override
  public void destroy() {
    if (filter0 != null) {
      filter0.destroy();
      filter0 = null;
    }
  }

  @Override
  public final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (filter0 == null) {
      throw new ServletException("filter is not initialized");
    }

    if (!(request instanceof HttpServletRequest && response instanceof HttpServletResponse)) {
      throw new ServletException("Only HTTP request is supported");
    }

    try {
      filter0.doFilter(new XiHttpRequestImpl((HttpServletRequest) request),
          new XiHttpResponseImpl((HttpServletResponse) response));
    } catch (IOException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ServletException(ex);
    }
  }

  /**
   * Xi Http Request Impl.
   * @author Lijun Liao (xipki)
   */
  private static class XiHttpRequestImpl implements XiHttpRequest {

    private final HttpServletRequest req;

    public XiHttpRequestImpl(HttpServletRequest req) {
      this.req = req;
    }

    @Override
    public String getHeader(String headerName) {
      return req.getHeader(headerName);
    }

    @Override
    public String getParameter(String paramName) {
      return req.getParameter(paramName);
    }

    @Override
    public String getMethod() {
      return req.getMethod();
    }

    @Override
    public String getServletPath() {
      return req.getServletPath();
    }

    @Override
    public String getContentType() {
      return req.getContentType();
    }

    @Override
    public Object getAttribute(String name) {
      return req.getAttribute(name);
    }

    @Override
    public String getContextPath() {
      return req.getContextPath();
    }

    @Override
    public X509Certificate[] getCertificateChain() {
      return (X509Certificate[]) req.getAttribute("jakarta.servlet.request.X509Certificate");
    }

    @Override
    public String getRequestURI() {
      return req.getRequestURI();
    }

    @Override
    public InputStream getInputStream() throws IOException {
      return req.getInputStream();
    }

    @Override
    public void setAttribute(String name, String value) {
      req.setAttribute(name, value);
    }

  }

  /**
   * Xi Http Response Impl.
   *
   * @author Lijun Liao (xipki)
   */
  private static class XiHttpResponseImpl implements XiHttpResponse {

    private final HttpServletResponse resp;

    public XiHttpResponseImpl(HttpServletResponse resp) {
      this.resp = Args.notNull(resp, "resp");
    }

    @Override
    public void setStatus(int sc) {
      resp.setStatus(sc);
    }

    @Override
    public void sendError(int sc) throws IOException {
      resp.sendError(sc);
    }

    @Override
    public void setContentType(String type) {
      resp.setContentType(type);
    }

    @Override
    public void addHeader(String name, String value) {
      resp.addHeader(name, value);
    }

    @Override
    public void setHeader(String name, String value) {
      resp.setHeader(name, value);
    }

    @Override
    public void setContentLength(int len) {
      resp.setContentLength(len);
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      return resp.getOutputStream();
    }
  }

}
