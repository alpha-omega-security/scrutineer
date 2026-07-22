# Java and JVM injection reference

Load for Java, Kotlin, Scala, Spring, Jackson, SnakeYAML, Log4j, Freemarker,
Velocity, JSP/EL, scripting engines, native serialization, and process builders.

## Version facts to check

- SnakeYAML before 2.0 defaulted to a constructor capable of creating arbitrary
  Java objects when callers used `new Yaml()` or `Constructor`. SnakeYAML 2.0
  changed defaults toward `SafeConstructor`; still verify explicit constructors
  and type descriptions.
- Jackson `enableDefaultTyping` and `@JsonTypeInfo(use = Id.CLASS)` are unsafe
  when untrusted JSON can select classes. Jackson 2.10 introduced
  `PolymorphicTypeValidator`; absence of an allowlist is the key issue.
- Log4j JNDI RCE was fixed in 2.17.1. Only report logging of attacker strings
  here when the project is on a vulnerable Log4j line and the relevant lookup
  behavior is enabled/reachable.
- Spring4Shell CVE-2022-22965 needs Spring Framework 5.3.0-5.3.17,
  5.2.0-5.2.19, JDK 9+, and a vulnerable binding/deployment shape such as WAR
  on Tomcat. Do not report generic Spring binding without those conditions.
- Apache Commons Text string interpolation RCE is fixed in 1.10.0; earlier
  `StringSubstitutor` with dangerous lookups can execute commands or scripts.

## Dangerous APIs

- Command execution: `Runtime.getRuntime().exec(String)`, `ProcessBuilder`
  invoking `sh -c`, `bash -c`, `cmd.exe /c`, and wrappers concatenating one
  command string.
- Dynamic execution: `ScriptEngine.eval(user)`, Spring SpEL
  `parseExpression(user).getValue()`, MVEL/OGNL/JEXL expression evaluation,
  reflection dispatch from user-selected class or method names, and dynamic
  class loading.
- Deserialization: `ObjectInputStream.readObject` on network/request bytes,
  unrestricted Jackson polymorphic typing, SnakeYAML unsafe constructors,
  XStream before hardened allowlists, and Hessian/Kryo/FST on untrusted bytes.
- Templates: Freemarker/Velocity/Thymeleaf template source or expression text
  controlled by a user, dynamic template path selection outside an allowlist,
  and exposed utility classes such as Freemarker `Execute`.

## Safe or non-reportable forms

- `new ProcessBuilder("git", "clone", "--", userUrl)` with a literal program
  does not invoke a shell.
- Jackson binding into a concrete DTO without default typing is not object
  construction RCE.
- SnakeYAML with `SafeConstructor` or schema-bound primitive DTOs is normally
  safe.
- Logging user strings on Log4j 2.17.1+ is not Log4Shell.

## Commands

```bash
rg -n 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder|/bin/sh|cmd\.exe|bash -c' ./src
rg -n 'ScriptEngine|parseExpression|MVEL|OGNL|Jexl|Class\.forName|URLClassLoader' ./src
rg -n 'ObjectInputStream|readObject|enableDefaultTyping|JsonTypeInfo|new Yaml|Constructor\(' ./src
rg -n 'freemarker|Velocity|Thymeleaf|StringSubstitutor|log4j|spring-framework' ./src
```
