// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.datasource;

import org.xipki.codec.util.Args;
import org.xipki.util.conf.ConfigurableProperties;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.util.conf.FileOrValue;
import org.xipki.codec.util.IoUtil;
import org.xipki.util.password.PasswordResolverException;
import org.xipki.util.password.Passwords;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Data Source Factory.
 *
 * @author Lijun Liao (xipki)
 */
public class DataSourceFactory {

  public DataSourceWrapper createDataSource(String name, FileOrValue conf)
      throws IOException, InvalidConfException {
    return createDataSource(name, conf, null);
  }

  /**
   * Create a {@link DataSourceWrapper} from the configuration.
   *
   * @param name the datasource name
   * @param conf the configuration
   * @param basedir the base directory, against which the relative configuration file and the
   *                relative path of an embedded H2 / HSQLDB database are resolved. May be
   *                {@code null}.
   * @return the created datasource wrapper.
   * @throws IOException if IO error occurs while reading the configuration.
   */
  public DataSourceWrapper createDataSource(String name, FileOrValue conf, String basedir)
      throws IOException, InvalidConfException {
    ConfigurableProperties props;
    try (Reader reader = new StringReader(Args.notNull(conf, "conf").readContent(basedir))) {
      props = new ConfigurableProperties();
      props.load(reader);
    }

    return createDataSource(name, props, basedir);
  } // method createDataSource

  /**
   * Create a {@link DataSourceWrapper} from the configuration stored in the
   * input stream.
   * <p>The specified stream remains open after this method returns.
   *
   * @param name the datasource name
   * @param conf the configuration
   * @return the created datasource wrapper.
   * @throws IOException if IO error occurs while reading the input stream.
   */
  public DataSourceWrapper createDataSource(String name, InputStream conf)
      throws IOException, InvalidConfException {
    return createDataSource(name, conf, null);
  }

  /**
   * Create a {@link DataSourceWrapper} from the configuration stored in the
   * input stream.
   * <p>The specified stream remains open after this method returns.
   *
   * @param name the datasource name
   * @param conf the configuration
   * @param basedir the base directory, against which the relative path of an embedded H2 /
   *                HSQLDB database is resolved. May be {@code null}.
   * @return the created datasource wrapper.
   * @throws IOException if IO error occurs while reading the input stream.
   */
  public DataSourceWrapper createDataSource(String name, InputStream conf, String basedir)
      throws IOException, InvalidConfException {
    ConfigurableProperties config = new ConfigurableProperties();
    config.load(Args.notNull(conf, "conf"));
    return createDataSource(name, config, basedir);
  } // method createDataSource

  public DataSourceWrapper createDataSource(String name, ConfigurableProperties conf)
      throws InvalidConfException {
    return createDataSource(name, conf, null);
  }

  /**
   * Create a {@link DataSourceWrapper} from the configuration.
   *
   * @param name the datasource name
   * @param conf the configuration
   * @param basedir the base directory, against which the relative path of an embedded H2 /
   *                HSQLDB database is resolved. May be {@code null}.
   * @return the created datasource wrapper.
   */
  public DataSourceWrapper createDataSource(
      String name, ConfigurableProperties conf, String basedir) throws InvalidConfException {
    DatabaseType databaseType;
    String className = Args.notNull(conf, "conf").getProperty("dataSourceClassName");
    if (className != null) {
      databaseType = DatabaseType.forDataSourceClass(className);
    } else {
      className = conf.getProperty("driverClassName");
      if (className != null) {
        databaseType = DatabaseType.forDriver(className);
      } else {
        String jdbcUrl = Optional.ofNullable(conf.getProperty("jdbcUrl"))
            .orElseThrow(() -> new IllegalArgumentException("none of the properties " +
                "dataSourceClassName, driverClassName and jdbcUrl is configured"));

        databaseType = DatabaseType.forJdbcUrl(jdbcUrl);
      }
    }

    try {
      String password = conf.getProperty("password");
      if (password != null) {
        password = new String(Passwords.resolvePassword(password));
        conf.setProperty("password", password);
      }

      password = conf.getProperty("dataSource.password");
      if (password != null) {
        password = new String(Passwords.resolvePassword(password));
        conf.setProperty("dataSource.password", password);
      }
    } catch (PasswordResolverException ex) {
      throw new InvalidConfException("error resolving password");
    }

    /*
     * Resolve the file path (leading '~', or relative to basedir) like
     *   dataSource.url = jdbc:h2:~/xipki/db/h2/ocspcrl
     *   dataSource.url = jdbc:h2:./db/h2/ocspcrl
     *   dataSource.url = \
     *     jdbc:hsqldb:file:~/xipki/db/hsqldb/ocspcache;sql.syntax_pgs=true
     */
    String dataSourceUrl = conf.getProperty("dataSource.url");
    if (dataSourceUrl == null) {
      // mariadb
      if (databaseType == DatabaseType.MARIADB) {
        String serverName = conf.remove("dataSource.serverName");
        String port = conf.remove("dataSource.port");
        if (port == null) {
          port = "3306";
        }
        String databaseName = conf.remove("dataSource.databaseName");
        dataSourceUrl = "jdbc:mariadb://" + serverName + ":" + port + "/" + databaseName;
        conf.setProperty("dataSource.url", dataSourceUrl);
      }
    } else {
      String newUrl = resolveEmbeddedDbUrl(basedir, dataSourceUrl);
      if (!newUrl.equals(dataSourceUrl)) {
        conf.setProperty("dataSource.url", newUrl);
      }
    }

    for (String key : conf.propertyNames()) {
      if (key.startsWith("sqlscript.") || key.startsWith("liquibase.")) {
        conf.remove(key);
      }
    }

    return DataSourceWrapper.createDataSource(name, conf, databaseType);
  } // method createDataSource

  /**
   * Resolves the file path of an embedded H2 database ({@code jdbc:h2:[file:]<path>}) or
   * HSQLDB file database ({@code jdbc:hsqldb:file:<path>}). Other URLs, and H2 in-memory,
   * server and zip URLs, are returned unchanged.
   */
  static String resolveEmbeddedDbUrl(String basedir, String url) {
    String prefix;
    if (url.startsWith("jdbc:h2:file:")) {
      prefix = "jdbc:h2:file:";
    } else if (url.startsWith("jdbc:h2:")) {
      prefix = "jdbc:h2:";
      String rest = url.substring(prefix.length());
      for (String p : new String[]{"mem:", "tcp:", "ssl:", "zip:"}) {
        if (rest.startsWith(p)) {
          return url;
        }
      }
    } else if (url.startsWith("jdbc:hsqldb:file:")) {
      prefix = "jdbc:hsqldb:file:";
    } else {
      return url;
    }

    String rest = url.substring(prefix.length());
    int idx = rest.indexOf(';');
    String path = idx == -1 ? rest : rest.substring(0, idx);
    if (path.isEmpty()) {
      return url;
    }

    String suffix = idx == -1 ? "" : rest.substring(idx);
    return prefix + IoUtil.resolvePath(basedir, path) + suffix;
  }

  public DataSourceWrapper createDataSourceForFile(String name, String confFile)
      throws IOException, InvalidConfException {
    return createDataSourceForFile(name, confFile, null);
  }

  /**
   * Create a {@link DataSourceWrapper} from the configuration file.
   *
   * @param name the datasource name
   * @param confFile the configuration file
   * @param basedir the base directory, against which the relative configuration file and the
   *                relative path of an embedded H2 / HSQLDB database are resolved. May be
   *                {@code null}.
   * @return the created datasource wrapper.
   * @throws IOException if IO error occurs while reading the configuration file.
   */
  public DataSourceWrapper createDataSourceForFile(String name, String confFile, String basedir)
      throws IOException, InvalidConfException {
    String path = IoUtil.resolvePath(basedir, Args.notBlank(confFile, "confFile"));
    try (InputStream fileIn = Files.newInputStream(Paths.get(path))) {
      return createDataSource(name, fileIn, basedir);
    }
  }

}
