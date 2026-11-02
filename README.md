# Vulnerable Java corpus generator

AI-generated python utility. `generate_vulns.py` generates a synthetic corpus of **intentionally vulnerable** Java servlets for SAST benchmarking and testing. 


### ******** Use the generated code for scanning. DO NOT deploy the output code ********


| Type | Source | Sink |
|------|--------|------|
| `sqli` – SQL injection | `req.getParameter(...)` | `Statement.executeQuery/executeUpdate/execute` |
| `cmdi` – Command injection | `req.getParameter(...)` | `Runtime.getRuntime().exec(...)` |
| `xss` – Reflected XSS | `req.getParameter(...)` | `resp.getWriter().write/print/println` |

Each flow passes the tainted value through 3–10 hops (assignments, helper calls, calls into further methods) before reaching the sink.

## Requirements

Python 3.8+ (standard library only). To compile the output: a JDK and `javax.servlet-api` (a `pom.xml` is generated).

## Usage

```bash
# Random 100k–600k flows per type, ~500 files total
python generate_vulns.py --out out

# Explicit counts, reproducible
python generate_vulns.py --out out --sqli 200000 --cmdi 150000 --xss 400000 --seed 42

# Small corpus for a quick try
python generate_vulns.py --out demo --sqli 3000 --cmdi 3000 --xss 3000 --files 6 --seed 1

# Only one type, shallower flows
python generate_vulns.py --out out --xss 100000 --min-depth 3 --max-depth 5
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--out` | `out` | Output directory |
| `--sqli` / `--cmdi` / `--xss` | random 100k–600k | Flows per type (`0` skips a type only if another is set) |
| `--files` | 500 | Total `.java` files, split by type in proportion to counts |
| `--min-depth` / `--max-depth` | 3 / 10 | Hops from source to sink |
| `--flows-per-class` | 200 | Flows per static nested class (avoids the JVM constant-pool limit) |
| `--seed` | random | Same seed and arguments give identical output |
| `--workers` | CPU count | Parallel processes |

## Output

```
out/
  pom.xml
  src/main/java/gen/{sqli,cmdi,xss}/Sqli0001.java, Cmdi0001.java, Xss0001.java ...
```

Each file is one `@WebServlet` whose `doGet`/`doPost` call every flow. Compile with `mvn -f out/pom.xml compile`.

## Example flow (XSS, depth 5, abridged from real output)

```java
static void flow8(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    String s1 = req.getParameter("email");
    s8_2(s1, resp);
}

static void s8_2(String field3, HttpServletResponse resp) throws Exception {
    String input6 = h8_4(field3);
    String msg7 = input6;
    String raw10 = h8_8(msg7);
    resp.getWriter().print(raw10);
}
```

## Notes

- A full default run is roughly 1–1.5 GB of source; compiling it takes time and memory.
- No ground-truth manifest or safe/sanitised cases are generated.
