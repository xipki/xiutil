// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.jline.reader.Highlighter;
import org.jline.reader.LineReader;
import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStringBuilder;
import org.jline.utils.AttributedStyle;

import java.io.File;

/**
 * Styling helpers for interactive shell input and traced command output.
 *
 * @author Lijun Liao (xipki)
 */
final class ShellCommandStyler {

  private static final AttributedStyle COMMAND_STYLE =
      AttributedStyle.DEFAULT.bold().foreground(AttributedStyle.CYAN);

  private static final AttributedStyle OPTION_STYLE =
      AttributedStyle.DEFAULT.bold().foreground(AttributedStyle.YELLOW);

  private static final AttributedStyle ARG_STYLE =
      AttributedStyle.DEFAULT.foreground(AttributedStyle.GREEN);

  private static final AttributedStyle VARIABLE_STYLE =
      AttributedStyle.DEFAULT.foreground(AttributedStyle.MAGENTA);

  private static final AttributedStyle QUOTED_STYLE =
      AttributedStyle.DEFAULT.foreground(AttributedStyle.BLUE);

  private static final ShellHighlighter HIGHLIGHTER = new ShellHighlighter();

  private ShellCommandStyler() {
  }

  static String formatAnsi(String line) {
    if (line == null || line.isEmpty()) {
      return "";
    }
    return HIGHLIGHTER.highlight(null, line).toAnsi();
  }

  static Highlighter highlighter() {
    return new ShellHighlighter();
  }

  private static boolean looksLikeArgumentToken(String token) {
    return token.contains("/") || token.contains(".") || token.contains(File.separator)
        || token.startsWith("~");
  }

  private static AttributedStyle tokenStyle(String token, boolean firstToken) {
    if (firstToken) {
      return COMMAND_STYLE;
    } else if (token.startsWith("-")) {
      return OPTION_STYLE;
    } else if (token.startsWith("${") || token.startsWith("$")) {
      return VARIABLE_STYLE;
    } else if (ShellVariableSupport.isSimpleQuotedLiteral(token)) {
      return QUOTED_STYLE;
    } else if (looksLikeArgumentToken(token)) {
      return ARG_STYLE;
    } else {
      return null;
    }
  }

  static class ShellHighlighter implements Highlighter {

    @Override
    public AttributedString highlight(LineReader reader, String buffer) {
      if (buffer == null || buffer.isEmpty()) {
        return new AttributedString("");
      }

      AttributedStringBuilder sb = new AttributedStringBuilder(buffer.length());
      int i = 0;
      int tokenIndex = 0;
      while (i < buffer.length()) {
        if (Character.isWhitespace(buffer.charAt(i))) {
          sb.append(buffer.charAt(i));
          i++;
          continue;
        }

        int start = i;
        boolean inSingle = false;
        boolean inDouble = false;
        while (i < buffer.length()) {
          char ch = buffer.charAt(i);
          if (ch == '\'' && !inDouble) {
            inSingle = !inSingle;
          } else if (ch == '"' && !inSingle) {
            inDouble = !inDouble;
          } else if (Character.isWhitespace(ch) && !inSingle && !inDouble) {
            break;
          }
          i++;
        }

        String token = buffer.substring(start, i);
        AttributedStyle style = tokenStyle(token, tokenIndex == 0);
        if (style != null) {
          sb.append(token, style);
        } else {
          sb.append(token);
        }
        tokenIndex++;
      }

      return sb.toAttributedString();
    }
  }

}
