#!/usr/bin/env python3
"""Generate a synthetic corpus of intentionally vulnerable Java servlets.

Intended as a SAST benchmark / test corpus (never deploy the output).

Vulnerability types, each a direct source -> sink taint flow:
  sqli  SQL injection       request parameter -> Statement.execute*/executeQuery
  cmdi  Command injection   request parameter -> Runtime.getRuntime().exec
  xss   Reflected XSS       request parameter -> HttpServletResponse writer

Flow depth is counted in hops (edges) from the request parameter to the sink:
    String a = req.getParameter("x");   // source
    String b = a;                       // hop 1 (assignment)
    String c = h(b);                    // hop 2 (helper call)
    sink(c);                            // hop 3 (call into a method holding the sink)
Each flow gets a random depth in [--min-depth, --max-depth] (default 3..10).

Layout: the corpus is capped at --files .java files in total (default 500), split
between the types in proportion to their counts. Every file is one servlet class
whose flows are grouped in static nested classes (each nested class compiles to its
own class file, so no class hits the JVM 64K constant-pool limit).
"""
import argparse
import multiprocessing as mp
import os
import random
import sys
import time

WORDS = ["data", "input", "value", "param", "text", "item", "name", "query", "token",
         "payload", "content", "field", "entry", "arg", "raw", "tmp", "buf", "msg",
         "s", "str", "line", "key", "term", "id", "info"]
KEYS = ["id", "name", "q", "search", "user", "file", "host", "cmd", "page", "msg",
        "title", "city", "email", "ref", "lang", "filter", "sort", "view"]
TABLES = ["users", "orders", "products", "accounts", "items", "customers", "logs", "sessions",
          "invoices", "employees", "messages", "payments"]
COLUMNS = ["id", "name", "email", "status", "title", "city", "code", "owner", "category", "label"]
CMD_PREFIX = ["ping -c 1 ", "ls ", "cat ", "nslookup ", "echo ", "whoami ", "dig ", "grep -r ",
              "wc -l ", "stat ", "tar tf ", "du -sh "]
HTML_WRAP = [("<html><body>Hello ", "</body></html>"), ("<div>", "</div>"), ("<p>Result: ", "</p>"),
             ("<h1>", "</h1>"), ("<span class=\\\"u\\\">", "</span>"), ("<td>", "</td>")]

HEADER = """package gen.{kind};

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;

"""

POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>gen</groupId>
  <artifactId>vuln-corpus</artifactId>
  <version>1.0</version>
  <packaging>jar</packaging>
  <properties>
    <maven.compiler.source>8</maven.compiler.source>
    <maven.compiler.target>8</maven.compiler.target>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>javax.servlet</groupId>
      <artifactId>javax.servlet-api</artifactId>
      <version>4.0.1</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>
"""

KINDS = ("sqli", "cmdi", "xss")
CLASS_PREFIX = {"sqli": "Sqli", "cmdi": "Cmdi", "xss": "Xss"}


class Builder:
    """Builds the methods of a single flow."""

    def __init__(self, rng, kind, fid):
        self.rng, self.kind, self.fid = rng, kind, fid
        self.n = 0
        self.methods = []  # each a list of source lines, unindented

    def var(self):
        self.n += 1
        return "%s%d" % (self.rng.choice(WORDS), self.n)

    def name(self, prefix):
        self.n += 1
        return "%s%d_%d" % (prefix, self.fid, self.n)


def source_line(b, var):
    key = b.rng.choice(KEYS)
    form = b.rng.choices(
        ['req.getParameter("%s")', 'req.getParameterValues("%s")[0]', 'req.getParameterMap().get("%s")[0]'],
        weights=[8, 1, 1])[0]
    return "String %s = %s;" % (var, form % key)


def helper(b):
    """A pass-through helper method; returns its name."""
    name = b.name("h")
    p = b.var()
    body = b.rng.choice([
        ["return %s;" % p],
        ["String t = %s;" % p, "return t;"],
        ["return %s != null ? %s : \"\";" % (p, p)],
    ])
    b.methods.append(["private static String %s(String %s) {" % (name, p)] +
                     ["    " + l for l in body] + ["}"])
    return name


def sink(b, v):
    r = b.rng
    if b.kind == "sqli":
        t, c, c2 = r.choice(TABLES), r.choice(COLUMNS), r.choice(COLUMNS)
        stmt, call = r.choice([
            ("SELECT * FROM %s WHERE %s = '\" + %s + \"'" % (t, c, v), "executeQuery"),
            ("SELECT %s, %s FROM %s WHERE %s = \" + %s + \"" % (c, c2, t, c, v), "executeQuery"),
            ("UPDATE %s SET %s = 1 WHERE %s = '\" + %s + \"'" % (t, c2, c, v), "executeUpdate"),
            ("DELETE FROM %s WHERE %s = '\" + %s + \"'" % (t, c, v), "execute"),
            ("SELECT * FROM %s WHERE %s LIKE '%%\" + %s + \"%%'" % (t, c, v), "execute"),
        ])
        query = '"%s"' % stmt
        lines = ['Connection conn = DriverManager.getConnection("jdbc:h2:mem:%s");' % r.choice(TABLES),
                 "Statement st = conn.createStatement();"]
        if r.random() < 0.6:
            lines += ["String sql = %s;" % query, "st.%s(sql);" % call]
        else:
            lines += ["st.%s(%s);" % (call, query)]
        return lines
    if b.kind == "cmdi":
        pre = r.choice(CMD_PREFIX)
        form = r.choice(["str", "str", "direct", "array"])
        if form == "direct":
            return ["Runtime.getRuntime().exec(%s);" % v]
        lines = ['String command = "%s" + %s;' % (pre, v)]
        if form == "str":
            lines.append(r.choice(["Runtime.getRuntime().exec(command);",
                                   "Runtime rt = Runtime.getRuntime();\nrt.exec(command);"]))
        else:
            lines.append('Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", command});')
        return lines
    pre, post = r.choice(HTML_WRAP)
    lines = []
    if r.random() < 0.4:
        lines.append('resp.setContentType("text/html");')
    expr = '"%s" + %s + "%s"' % (pre, v, post)
    form = r.choice(["write", "println", "print", "outw", "direct"])
    if form == "write":
        lines.append("resp.getWriter().write(%s);" % expr)
    elif form == "direct":
        lines.append("resp.getWriter().print(%s);" % v)
    else:
        lines.append("PrintWriter out = resp.getWriter();")
        lines.append("out.%s(%s);" % ({"println": "println", "print": "print", "outw": "write"}[form], expr))
    return lines


def emit_method(b, name, hops, entry):
    xss = b.kind == "xss"
    lines = []
    var = b.var()
    if entry:
        params = "HttpServletRequest req, HttpServletResponse resp"
        lines.append(source_line(b, var))
    else:
        params = "String %s%s" % (var, ", HttpServletResponse resp" if xss else "")
    descended = False
    while hops > 1:
        k = b.rng.choice(("assign", "assign", "call", "call", "descend"))
        if k == "assign":
            nv = b.var()
            lines.append("String %s = %s;" % (nv, var))
            var = nv
        elif k == "call":
            h = helper(b)
            nv = b.var()
            lines.append("String %s = %s(%s);" % (nv, h, var))
            var = nv
        else:
            m2 = b.name("s")
            emit_method(b, m2, hops - 1, False)
            lines.append("%s(%s%s);" % (m2, var, ", resp" if xss else ""))
            descended = True
            break
        hops -= 1
    if not descended:
        lines += sink(b, var)
    flat = []
    for l in lines:
        flat.extend(l.split("\n"))
    b.methods.append(["static void %s(%s) throws Exception {" % (name, params)] +
                     ["    " + l for l in flat] + ["}"])


def gen_flow(rng, kind, fid, min_d, max_d):
    b = Builder(rng, kind, fid)
    entry = "flow%d" % fid
    emit_method(b, entry, rng.randint(min_d, max_d), True)
    return entry, b.methods


def gen_file(job):
    kind, idx, nflows, seed, outdir, per_class, min_d, max_d = job
    rng = random.Random("%s:%s:%d" % (seed, kind, idx))
    cls = "%s%04d" % (CLASS_PREFIX[kind], idx)
    groups = []
    fid = 0
    remaining = nflows
    while remaining > 0:
        n = min(per_class, remaining)
        remaining -= n
        entries, methods = [], []
        for _ in range(n):
            fid += 1
            e, ms = gen_flow(rng, kind, fid, min_d, max_d)
            entries.append(e)
            methods.extend(ms)
        groups.append((entries, methods))

    out = [HEADER.format(kind=kind)]
    out.append('@WebServlet("/%s/%04d")\n' % (kind, idx))
    out.append("public class %s extends HttpServlet {\n" % cls)
    out.append("    @Override\n    protected void doGet(HttpServletRequest req, HttpServletResponse resp)"
               " throws ServletException, IOException {\n        process(req, resp);\n    }\n\n")
    out.append("    @Override\n    protected void doPost(HttpServletRequest req, HttpServletResponse resp)"
               " throws ServletException, IOException {\n        process(req, resp);\n    }\n\n")
    out.append("    private void process(HttpServletRequest req, HttpServletResponse resp)"
               " throws ServletException, IOException {\n")
    for g in range(len(groups)):
        out.append("        G%d.run(req, resp);\n" % g)
    out.append("    }\n")
    for g, (entries, methods) in enumerate(groups):
        out.append("\n    static final class G%d {\n" % g)
        out.append("        static void run(HttpServletRequest req, HttpServletResponse resp) {\n")
        for e in entries:
            out.append("            try { %s(req, resp); } catch (Exception e) { }\n" % e)
        out.append("        }\n")
        for m in methods:
            out.append("\n")
            for l in m:
                out.append("        " + l + "\n")
        out.append("    }\n")
    out.append("}\n")

    path = os.path.join(outdir, "src", "main", "java", "gen", kind, cls + ".java")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("".join(out))
    return kind, nflows


def split_evenly(total, parts):
    base, extra = divmod(total, parts)
    return [base + (1 if i < extra else 0) for i in range(parts)]


def allocate_files(counts, total_files):
    total = sum(counts.values())
    files = {k: max(1, round(total_files * c / total)) for k, c in counts.items()}
    # fix rounding so the sum equals total_files
    while sum(files.values()) != total_files:
        k = max(files, key=files.get) if sum(files.values()) > total_files else min(files, key=files.get)
        files[k] += -1 if sum(files.values()) > total_files else 1
    return files


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="out", help="output directory (default: ./out)")
    ap.add_argument("--sqli", type=int, help="SQLi flows (default: random 100k-600k)")
    ap.add_argument("--cmdi", type=int, help="command injection flows (default: random 100k-600k)")
    ap.add_argument("--xss", type=int, help="reflected XSS flows (default: random 100k-600k)")
    ap.add_argument("--files", type=int, default=500, help="total .java files across all types (default 500)")
    ap.add_argument("--min-depth", type=int, default=3)
    ap.add_argument("--max-depth", type=int, default=10)
    ap.add_argument("--flows-per-class", type=int, default=200,
                    help="flows per static nested class (keeps each class file small)")
    ap.add_argument("--seed", default=None, help="seed for reproducible output (default: random)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    a = ap.parse_args()

    if not 1 <= a.min_depth <= a.max_depth:
        ap.error("need 1 <= --min-depth <= --max-depth")
    seed = a.seed if a.seed is not None else str(random.SystemRandom().randrange(1 << 32))
    top = random.Random("counts:" + seed)
    counts = {k: (getattr(a, k) if getattr(a, k) is not None else top.randint(100_000, 600_000)) for k in KINDS}
    if any(c < 0 for c in counts.values()) or sum(counts.values()) == 0:
        ap.error("counts must be >= 0 and not all zero")
    counts = {k: c for k, c in counts.items() if c > 0}
    if a.files < len(counts):
        ap.error("--files must be at least the number of vulnerability types generated")
    files = allocate_files(counts, a.files)

    jobs = []
    for kind, c in counts.items():
        os.makedirs(os.path.join(a.out, "src", "main", "java", "gen", kind), exist_ok=True)
        for i, n in enumerate(split_evenly(c, files[kind]), 1):
            if n:
                jobs.append((kind, i, n, seed, a.out, a.flows_per_class, a.min_depth, a.max_depth))
    with open(os.path.join(a.out, "pom.xml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(POM)

    print("seed=%s  counts=%s  files=%s  workers=%d" % (seed, counts, files, a.workers))
    done = {k: 0 for k in counts}
    t0 = time.time()
    with mp.Pool(a.workers) as pool:
        for n, (kind, flows) in enumerate(pool.imap_unordered(gen_file, jobs, chunksize=1), 1):
            done[kind] += flows
            if n % 25 == 0 or n == len(jobs):
                print("  %d/%d files  %.0fs" % (n, len(jobs), time.time() - t0), flush=True)
    print("done: %s  total=%d" % (done, sum(done.values())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
