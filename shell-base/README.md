# shell-base

An interactive shell for [picocli](https://picocli.info/) applications, built on
[JLine](https://github.com/jline/jline3). Give it a picocli root command and you get:

- an interactive REPL with tab completion, syntax highlighting and persistent history
- one-shot execution when command-line arguments are given
- a small scripting language (`source`, variables, `if`/`elif`/`else`, `for`, command
  substitution)
- a set of built-in commands (`help`, `set`, `echo`, `less`, `exit`, ...)

shell-base is extracted from the [XiPKI](https://github.com/xipki/xipki) project.

## Requirements

- Java 11 or later
- Maven 3 (to build)

## Build

```sh
mvn clean install
```

## Maven dependency

```xml
<dependency>
  <groupId>org.xipki.util</groupId>
  <artifactId>shell-base</artifactId>
  <version>7.0.0-SNAPSHOT</version>
</dependency>
```

shell-base logs through SLF4J; add an SLF4J binding of your choice to your application.

## Quick start

```java
import org.xipki.shell.Completion;
import org.xipki.shell.PicocliShell;
import org.xipki.shell.ShellBaseCommand;
import org.xipki.shell.completer.FilePathCompleter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "mytool", subcommands = {MyTool.Hello.class})
public class MyTool {

  @Command(name = "hello", description = "Say hello", mixinStandardHelpOptions = true)
  static class Hello extends ShellBaseCommand {

    @Option(names = "--name", description = "who to greet")
    @Completion(values = {"alice", "bob"})
    private String name = "world";

    @Option(names = "--out", description = "output file")
    @Completion(FilePathCompleter.class)
    private String out;

    @Override
    public void run() {
      println("Hello, " + name + "!");
    }
  }

  public static void main(String[] args) throws Exception {
    // No arguments: interactive shell. With arguments: run them once and exit.
    System.exit(PicocliShell.run("mytool> ", new MyTool(), args));
  }
}
```

```text
$ mytool
Welcome to mytool 1.0.0
Type 'help' for commands, 'exit' to quit.
mytool> hello --name alice
Hello, alice!

$ mytool hello --name bob
Hello, bob!
```

### API overview

| Type | Purpose |
|------|---------|
| `PicocliShell` | Entry point. `run(prompt, rootCommand[, args])` starts the shell; an instance also offers `executeLine(...)`, `executeScript(...)`, `commandLine()` and `stop()`. |
| `ShellBaseCommand` | Optional base class for commands, with helpers such as `println`, `readPrompt`, `readSecret`, `confirmAction`, `saveVerbose` and `toBigInt`. |
| `@Completion` | Annotation on an option or parameter field: static `values` and/or a `CompletionProvider` class. |
| `CompletionProvider` | Interface for dynamic completion candidates. |
| `completer.FilePathCompleter`, `completer.DirPathCompleter` | Complete file or directory paths. |
| `completer.AbstractSetCompleter` | Base class for completers with a fixed set of tokens (strings or enum constants). |

## Interactive features

- **Completion** of subcommands, options and values (from `@Completion`).
- **History** is stored in `~/.xipki/<command-name>.history`. Values of `--password` and
  `--pin` are masked (`********`) before being written; variable references such as
  `${env:PASSWORD}` are kept as they are.
- **Help**: `help [command ...]`, or `-h` / `--help` on any command.
- `Ctrl-C` cancels the current line; `Ctrl-D` leaves the shell.

## Built-in commands

| Command | Description |
|---------|-------------|
| `help [command ...]` | Show help for a command |
| `source <file> [args ...]` | Execute commands from a script file |
| `set <name> <value>` | Set a shell variable |
| `unset <name>` | Remove a shell variable |
| `echo [text ...]` | Print text |
| `less <file>` | Page through a text file |
| `sleep <seconds>` | Sleep for the given number of seconds |
| `clear` | Clear the screen |
| `java-version [--full]` | Print the Java version |
| `exception <message>` | Throw an exception with the given message |
| `return` | Stop executing the current script |
| `exit`, `quit` | Exit the shell |

## Scripting

Scripts are run with `source <file> [args ...]`, or from Java with `executeScript(...)`.
A relative script path is resolved against the directory of the calling script (or the
current directory), and then against the shell home given by the system property
`org.xipki.shell.home`.

```sh
# Lines starting with '#' or '//' are comments.
set NAME world
set ITEMS [a b c]

if ${1} eq ""
  echo "usage: source demo.sh <count>"
  return
fi

if $1 gt 10
  echo "big"
elif $1 in 1 2 3
  echo "small"
else
  echo "medium"
fi

for item in ${ITEMS}
  hello --name ${item}
done

set JAVA $(java-version)
echo "Java ${JAVA}, home ${env:HOME}, user ${sys:user.name}"

hello --name ${NAME} \
  --out ~/hello.txt
```

- **Variables**: `$NAME` / `${NAME}`; positional script arguments `$1`, `$2`, ...;
  environment variables `${env:NAME}`; Java system properties `${sys:name}`.
  Escape with a backslash (`\${NAME}`) to keep the text literal.
- **Lists**: `set X [a b c]`.
- **Conditions** (`if` / `elif`): `eq`, `neq`, `in`, and the numeric comparisons `gt`, `ge`,
  `lt`, `le`. Combine alternatives with `or` or `|`.
- **Command substitution**: `$(command)` is replaced with the command's output.
- **Line continuation**: a trailing `\` joins the next line.
- **Tracing**: `set SCRIPT_TRACE true` prints each command before it runs.
- Commands that are not shell commands are run as external processes, with the script's
  directory as the working directory.
- A script that sources itself, directly or indirectly, is rejected.

## License

[Apache License 2.0](LICENSE)
