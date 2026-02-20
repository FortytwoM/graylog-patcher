import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Single-pass bytecode patcher for Graylog Enterprise plugin JAR.
 *
 * Usage: java UnifiedPatcher <input.jar> <output.jar>
 */
public class UnifiedPatcher {

    static final String LICENSE_ID = "generated-license-001";
    static final String CONTRACT_ID = "a1b2c3d4e5f60789012340ab";

    private static final Map<String, int[]> summary = new LinkedHashMap<>();

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: java UnifiedPatcher <input.jar> <output.jar>");
            System.exit(1);
        }
        String jarPath = args[0];
        String outPath = args[1];
        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            System.err.println("JAR not found: " + jarPath);
            System.exit(1);
        }

        try {
            ClassPool pool = ClassPool.getDefault();
            pool.insertClassPath(jarPath);

            Map<String, byte[]> patches = new LinkedHashMap<>();

            patchJwtParser(pool, patches);
            patchLicenseChecker(pool, patches);
            patchDefaultLicenseManager(pool, patches);
            patchDrawdownService(pool, patches);
            patchLicenseManagerClient(pool, patches);
            patchTrafficThreshold(pool, patches);
            patchClassesByString(pool, jarPath, "has no contract ID", patches);
            patchClassesByString(pool, jarPath, "volume has been used", patches);

            if (patches.isEmpty()) {
                System.err.println("WARN: nothing was patched");
                System.exit(0);
            }

            File outFile = new File(outPath);
            if (jarPath.equals(outPath)) {
                File tmp = File.createTempFile("unified-patch-", ".jar");
                try {
                    replaceClassesInJar(jarFile, tmp, patches);
                    Files.move(tmp.toPath(), outFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    tmp.delete();
                }
            } else {
                replaceClassesInJar(jarFile, outFile, patches);
            }

            printSummary();
            System.out.println("[OK] Patched JAR written: " + outPath);
        } catch (Exception e) {
            e.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void patchJwtParser(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.jwt.JwtLicenseParser";
        String path = "org/graylog/plugins/license/jwt/JwtLicenseParser.class";
        try {
            CtClass cc = pool.get(cls);

            // parse(Claims): convert Date iat/exp/nbf to epoch seconds
            cc.getDeclaredMethod("parse", new CtClass[]{pool.get("io.jsonwebtoken.Claims")})
              .setBody(
                "{\n"
                + "  java.util.Map map = new java.util.HashMap(($1));\n"
                + "  Object v;\n"
                + "  v = map.get(\"iat\"); if (v != null) { if (v instanceof java.util.Date) map.put(\"iat\", Long.valueOf(((java.util.Date)v).getTime()/1000L)); else if (v instanceof Number) map.put(\"iat\", Long.valueOf(((Number)v).longValue())); }\n"
                + "  v = map.get(\"exp\"); if (v != null) { if (v instanceof java.util.Date) map.put(\"exp\", Long.valueOf(((java.util.Date)v).getTime()/1000L)); else if (v instanceof Number) map.put(\"exp\", Long.valueOf(((Number)v).longValue())); }\n"
                + "  v = map.get(\"nbf\"); if (v != null) { if (v instanceof java.util.Date) map.put(\"nbf\", Long.valueOf(((java.util.Date)v).getTime()/1000L)); else if (v instanceof Number) map.put(\"nbf\", Long.valueOf(((Number)v).longValue())); }\n"
                + "  org.graylog.plugins.license.api.LicenseClaims licenseClaims = (org.graylog.plugins.license.api.LicenseClaims) $0.objectMapper.convertValue(map, org.graylog.plugins.license.api.LicenseClaims.class);\n"
                + "  return org.graylog.plugins.license.api.License.fromClaims(licenseClaims);\n"
                + "}\n"
              );

            // parseToken(String): bypass signature verification
            cc.getDeclaredMethod("parseToken", new CtClass[]{pool.get("java.lang.String")})
              .setBody(
                "{\n"
                + "  try {\n"
                + "    return (io.jsonwebtoken.Claims) $0.jwtParser.parseSignedClaims((java.lang.CharSequence) $1).getPayload();\n"
                + "  } catch (io.jsonwebtoken.ExpiredJwtException e) {\n"
                + "    return e.getClaims();\n"
                + "  } catch (io.jsonwebtoken.PrematureJwtException e) {\n"
                + "    return e.getClaims();\n"
                + "  } catch (io.jsonwebtoken.security.SignatureException e) {\n"
                + "    String[] parts = ((String)$1).split(\"\\\\.\");\n"
                + "    if (parts.length != 3) throw new RuntimeException(\"Invalid JWT\");\n"
                + "    byte[] payloadBytes = java.util.Base64.getUrlDecoder().decode(parts[1]);\n"
                + "    String payloadStr = new String(payloadBytes, java.nio.charset.StandardCharsets.UTF_8);\n"
                + "    try {\n"
                + "      java.util.Map map = (java.util.Map) $0.objectMapper.readValue(payloadStr, java.util.Map.class);\n"
                + "      return new io.jsonwebtoken.impl.DefaultClaims(map);\n"
                + "    } catch (Exception ex) {\n"
                + "      throw new RuntimeException(\"Failed to decode JWT payload\", ex);\n"
                + "    }\n"
                + "  }\n"
                + "}\n"
              );

            // parse(LicenseDto): inject fallback contractId for drawdown licenses
            cc.getDeclaredMethod("parse", new CtClass[]{pool.get("org.graylog.plugins.license.mongo.LicenseDto")})
              .setBody(
                "{\n"
                + "  org.graylog.plugins.license.api.License license = $0.parse($1.license());\n"
                + "  if (license instanceof org.graylog.plugins.license.api.LicenseDrawdown) {\n"
                + "    org.graylog.plugins.license.api.LicenseDrawdown ld = (org.graylog.plugins.license.api.LicenseDrawdown) license;\n"
                + "    String cid = \"" + CONTRACT_ID + "\";\n"
                + "    try { Object co = $1.contractId(); if (co != null) { if (co instanceof java.util.Optional) { Object v = ((java.util.Optional)co).orElse(null); if (v != null && !v.toString().isEmpty()) cid = v.toString(); } else { String s = co.toString(); if (s != null && !s.isEmpty()) cid = s; } } } catch (Throwable t) { }\n"
                + "    if (cid == null || cid.isEmpty()) cid = \"" + CONTRACT_ID + "\";\n"
                + "    return ld.toBuilder().contractId(cid).build();\n"
                + "  }\n"
                + "  return license;\n"
                + "}\n"
              );

            patches.put(path, cc.toBytecode());
            cc.detach();
            record("JwtLicenseParser", 3);
        } catch (Exception e) {
            System.err.println("WARN: JwtLicenseParser: " + e.getMessage());
        }
    }

    private static void patchLicenseChecker(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.LicenseChecker";
        String path = "org/graylog/plugins/license/LicenseChecker.class";
        try {
            CtClass cc = pool.get(cls);
            int n = 0;

            for (CtMethod m : cc.getDeclaredMethods()) {
                if (!"checkStatus".equals(m.getName())) continue;
                CtClass[] params = m.getParameterTypes();
                if (params.length == 1 && params[0].getName().contains("License")) {
                    String rt;
                    try { rt = m.getReturnType().getName(); } catch (Exception e) { break; }
                    String ret = "void".equals(rt) ? "return;" : "boolean".equals(rt) ? "return true;" : "return null;";
                    String cond = "$1 != null && $1 instanceof org.graylog.plugins.license.api.License && \""
                                  + LICENSE_ID + "\".equals(((org.graylog.plugins.license.api.License)$1).id())";
                    try { m.insertBefore("if (" + cond + ") { " + ret + " }"); n++; }
                    catch (Exception ignored) {}
                    break;
                }
            }

            // Force active=true in checkLicenseStatus(License, ZonedDateTime, boolean)
            for (CtMethod cm : cc.getDeclaredMethods()) {
                if (!"checkLicenseStatus".equals(cm.getName())) continue;
                CtClass[] cp = cm.getParameterTypes();
                if (cp.length == 3 && cp[2].getName().equals("boolean")) {
                    try { cm.insertBefore("$3 = true;"); n++; } catch (Exception ignored) {}
                    break;
                }
            }

            for (CtMethod m : cc.getDeclaredMethods()) {
                String name = m.getName();
                if (name.contains("checkStatus") || name.contains("checkLicenseStatus")
                    || name.contains("collectActive") || name.contains("getOrCheck")) continue;

                CtClass[] params = m.getParameterTypes();
                String retType;
                try { retType = m.getReturnType().getName(); } catch (Exception e) { continue; }

                String earlyRet = earlyReturnForCollection(retType);
                if (earlyRet == null && "void".equals(retType)) earlyRet = "return;";
                if (earlyRet == null) continue;

                for (int i = 0; i < Math.min(params.length, 5); i++) {
                    if (!params[i].getName().contains("License")) continue;
                    String d = "$" + (i + 1);
                    String cond = d + " != null && " + d + " instanceof org.graylog.plugins.license.api.License && \""
                                  + LICENSE_ID + "\".equals(((org.graylog.plugins.license.api.License)" + d + ").id())";
                    try { m.insertBefore("if (" + cond + ") { " + earlyRet + " }"); n++; }
                    catch (Exception ignored) {}
                    break;
                }
            }

            if (n > 0) {
                patches.put(path, cc.toBytecode());
            }
            cc.detach();
            record("LicenseChecker", n);
        } catch (Exception e) {
            System.err.println("WARN: LicenseChecker: " + e.getMessage());
        }
    }

    private static void patchDefaultLicenseManager(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.DefaultLicenseManager";
        String path = "org/graylog/plugins/license/DefaultLicenseManager.class";
        try {
            CtClass cc = pool.get(cls);
            int n = 0;

            String fallback =
                "if ($_ != null && $_.isEmpty()) {" +
                "  java.util.Collection _lics = this.getLicenseStatuses();" +
                "  if (_lics != null && !_lics.isEmpty()) {" +
                "    $_ = java.util.Optional.of(_lics.iterator().next());" +
                "  }" +
                "}";

            for (CtMethod m : cc.getDeclaredMethods()) {
                String name = m.getName();
                String ret;
                try { ret = m.getReturnType().getName(); } catch (Exception e) { continue; }

                if ("hasValidLicense".equals(name) && "boolean".equals(ret)) {
                    m.insertBefore("{ return true; }");
                    n++;
                }
                if ("hasUnexpiredLicense".equals(name) && "boolean".equals(ret)) {
                    m.insertBefore("{ return true; }");
                    n++;
                }

                if ("getLicenseStatus".equals(name) && "java.util.Optional".equals(ret)) {
                    CtClass[] p = m.getParameterTypes();
                    if (p.length == 2 && p[0].getName().equals("java.net.URI")) {
                        try { m.insertAfter(fallback); n++; } catch (Exception ignored) {}
                    }
                }

                if ("getActiveLicenseStatus".equals(name) && "java.util.Optional".equals(ret)
                    && m.getParameterTypes().length == 0) {
                    try { m.insertAfter(fallback); n++; } catch (Exception ignored) {}
                }

                if ("findReportLicenseStatus".equals(name) && "java.util.Optional".equals(ret)) {
                    try { m.insertAfter(fallback); n++; } catch (Exception ignored) {}
                }
            }

            if (n > 0) {
                patches.put(path, cc.toBytecode());
            }
            cc.detach();
            record("DefaultLicenseManager", n);
        } catch (Exception e) {
            System.err.println("WARN: DefaultLicenseManager: " + e.getMessage());
        }
    }

    /**
     * Patches DrawdownLicenseService to bypass remote license.graylog.com calls.
     *
     * handleLicense flow:
     *   if (isContractStartDateReached && shouldCheckout) → signAndCheckout  [Path A]
     *   else → contractDbService.save(contract)                             [Path B → INACTIVE]
     *
     * Path B causes INACTIVE status (no checkout performed, no license saved).
     * Path A normally calls license.graylog.com via sign()/checkout().
     *
     * Fix: replace signAndCheckout body entirely via setBody (not insertBefore —
     * insertBefore corrupts its exception table → ClassFormatError). The replacement:
     *   1. saveContract(contract)                 → persist contract, get ID
     *   2. licenseService.saveLicense(jwt, cid)   → persist license, get License
     *   3. contractDbService.update(contract + licenseId) → link them
     * This mirrors what the original checkout lambda chain does after a successful
     * remote call, but without any network I/O.
     *
     * checkout() is a periodic job that also contacts the remote server — made no-op.
     */
    private static void patchDrawdownService(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.drawdown.DrawdownLicenseService";
        String path = "org/graylog/plugins/license/drawdown/DrawdownLicenseService.class";
        try {
            CtClass cc = pool.get(cls);
            int n = 0;

            for (CtMethod m : cc.getDeclaredMethods()) {
                String name = m.getName();
                String ret;
                try { ret = m.getReturnType().getName(); } catch (Exception e) { continue; }

                if ("checkout".equals(name) && "void".equals(ret)) {
                    try { m.insertBefore("{ return; }"); n++; } catch (Exception ignored) {}
                }

                if ("signAndCheckout".equals(name) && !("void".equals(ret))) {
                    try {
                        m.setBody(
                            "{\n"
                            + "  org.graylog.plugins.license.drawdown.contract.ContractDto _saved = saveContract($1);\n"
                            + "  org.graylog.plugins.license.api.License _lic =\n"
                            + "    licenseService.saveLicense($1.activationToken(), _saved.id());\n"
                            + "  contractDbService.update(_saved.toBuilder()\n"
                            + "    .licenseIds(java.util.Collections.singletonList(_lic.id()))\n"
                            + "    .build());\n"
                            + "  return null;\n"
                            + "}\n"
                        );
                        n++;
                    } catch (Exception e) {
                        System.err.println("WARN: signAndCheckout setBody: " + e.getMessage());
                    }
                }
            }

            if (n > 0) {
                patches.put(path, cc.toBytecode());
            }
            cc.detach();
            record("DrawdownLicenseService", n);
        } catch (Exception e) {
            System.err.println("WARN: DrawdownLicenseService: " + e.getMessage());
        }
    }

    /**
     * Safety net: both sign() and checkout() in LicenseManagerClient make HTTP calls
     * to license.graylog.com. Return null immediately so they never reach the network.
     */
    private static void patchLicenseManagerClient(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.drawdown.licensemanager.client.LicenseManagerClient";
        String path = "org/graylog/plugins/license/drawdown/licensemanager/client/LicenseManagerClient.class";
        try {
            CtClass cc = pool.get(cls);
            int n = 0;

            for (CtMethod m : cc.getDeclaredMethods()) {
                String name = m.getName();
                String ret;
                try { ret = m.getReturnType().getName(); } catch (Exception e) { continue; }

                if (("sign".equals(name) || "checkout".equals(name)) && !"void".equals(ret)) {
                    try { m.insertBefore("{ return null; }"); n++; } catch (Exception ignored) {}
                }
            }

            if (n > 0) {
                patches.put(path, cc.toBytecode());
            }
            cc.detach();
            record("LicenseManagerClient", n);
        } catch (Exception e) {
            System.err.println("WARN: LicenseManagerClient: " + e.getMessage());
        }
    }

    private static void patchTrafficThreshold(ClassPool pool, Map<String, byte[]> patches) {
        String cls = "org.graylog.plugins.license.drawdown.threshold.TrafficThresholdService";
        String path = "org/graylog/plugins/license/drawdown/threshold/TrafficThresholdService.class";
        try {
            CtClass cc = pool.get(cls);
            int n = 0;

            for (CtMethod m : cc.getDeclaredMethods()) {
                CtClass[] params = m.getParameterTypes();
                if (params.length != 1) continue;
                String pType = params[0].getName();
                String ret = m.getReturnType().getName();
                String earlyRet = earlyReturnForViolation(ret);
                if (earlyRet == null) continue;

                String cond = null;
                if (pType.endsWith(".License") || pType.equals("org.graylog.plugins.license.api.License"))
                    cond = "$1 != null && \"" + LICENSE_ID + "\".equals($1.id())";
                else if ("java.lang.String".equals(pType))
                    cond = "$1 != null && (\"" + CONTRACT_ID + "\".equals($1) || \"" + LICENSE_ID + "\".equals($1))";
                if (cond == null) continue;

                try { m.insertBefore("if (" + cond + ") { " + earlyRet + " }"); n++; }
                catch (Exception ignored) {}
            }

            if (n > 0) {
                patches.put(path, cc.toBytecode());
            }
            cc.detach();
            record("TrafficThresholdService", n);
        } catch (Exception e) {
            System.err.println("WARN: TrafficThresholdService: " + e.getMessage());
        }
    }

    private static void patchClassesByString(ClassPool pool, String jarPath,
                                              String searchString, Map<String, byte[]> patches) {
        List<String> found = findClassesContaining(jarPath, searchString);
        int totalMethods = 0;
        int classCount = 0;

        for (String classPath : found) {
            String className = classPath.replace("/", ".").replace(".class", "");
            try {
                CtClass cc = pool.get(className);
                int n = patchGenericViolationClass(cc);
                if (n > 0) {
                    patches.put(classPath, cc.toBytecode());
                    totalMethods += n;
                    classCount++;
                }
                cc.detach();
            } catch (Exception e) {
                System.err.println("WARN: " + className + ": " + e.getMessage());
            }
        }

        String label = "Dynamic(\"" + searchString.substring(0, Math.min(20, searchString.length())) + "...\")";
        record(label, totalMethods);
        if (classCount > 0) {
            System.err.println("[OK] " + label + ": " + classCount + " class(es), " + totalMethods + " method(s)");
        }
    }

    private static int patchGenericViolationClass(CtClass cc) throws Exception {
        int n = 0;
        for (CtMethod m : cc.getDeclaredMethods()) {
            String mname = m.getName();
            if (isStatusBuilder(mname)) continue;

            CtClass[] params = m.getParameterTypes();
            String ret;
            try { ret = m.getReturnType().getName(); } catch (Exception e) { continue; }
            String earlyRet = earlyReturnForViolation(ret);
            if (earlyRet == null) continue;

            for (int i = 0; i < params.length; i++) {
                String pname = params[i].getName();
                String d = "$" + (i + 1);
                String cond = null;

                if (pname.contains("License") && !pname.contains("Optional")) {
                    cond = d + " != null && " + d + " instanceof org.graylog.plugins.license.api.License && \""
                           + LICENSE_ID + "\".equals(((org.graylog.plugins.license.api.License)" + d + ").id())";
                } else if ("java.lang.String".equals(pname)) {
                    cond = d + " != null && (\"" + CONTRACT_ID + "\".equals(" + d + ") || \"" + LICENSE_ID + "\".equals(" + d + "))";
                }

                if (cond != null) {
                    try { m.insertBefore("if (" + cond + ") { " + earlyRet + " }"); n++; }
                    catch (Exception ignored) {}

                    if (pname.contains("LicenseDrawdown")) {
                        String noCid = d + " != null && (" + d + ".contractId() == null || \"\".equals(" + d + ".contractId()))";
                        try { m.insertBefore("if (" + noCid + ") { " + earlyRet + " }"); n++; }
                        catch (Exception ignored) {}
                    }
                    break;
                }
            }
        }
        return n;
    }

    private static boolean isStatusBuilder(String name) {
        return name.contains("checkStatus") || name.contains("checkLicenseStatus")
            || name.contains("collectActive") || name.contains("getOrCheck");
    }

    /** Early-return for collection/void types (used by LicenseChecker generic loop). */
    static String earlyReturnForCollection(String retType) {
        if (retType.startsWith("java.util.List")) return "return java.util.Collections.emptyList();";
        if (retType.startsWith("java.util.Set"))  return "return java.util.Collections.emptySet();";
        if (retType.startsWith("java.util.Collection")) return "return java.util.Collections.emptyList();";
        if (retType.startsWith("java.util.Optional"))   return "return java.util.Optional.empty();";
        return null;
    }

    /** Early-return for violation/check methods (boolean -> false). */
    static String earlyReturnForViolation(String retType) {
        if ("boolean".equals(retType)) return "return false;";
        if ("void".equals(retType)) return "return;";
        if (retType.startsWith("java.util.List")) return "return java.util.Collections.emptyList();";
        if (retType.startsWith("java.util.Set"))  return "return java.util.Collections.emptySet();";
        if (retType.startsWith("java.util.Collection")) return "return java.util.Collections.emptyList();";
        if (retType.startsWith("java.util.Optional"))   return "return java.util.Optional.empty();";
        return null;
    }

    /** Find .class entries in JAR whose bytecode contains the given UTF-8 string. */
    static List<String> findClassesContaining(String jarPath, String searchString) {
        List<String> result = new ArrayList<>();
        byte[] needle = searchString.getBytes(StandardCharsets.UTF_8);
        try (ZipFile zf = new ZipFile(jarPath)) {
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                if (!e.getName().endsWith(".class")) continue;
                try (InputStream is = zf.getInputStream(e)) {
                    byte[] data = is.readAllBytes();
                    if (contains(data, needle)) result.add(e.getName());
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            System.err.println("WARN: cannot scan JAR: " + e.getMessage());
        }
        return result;
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    /** Single-pass JAR rewrite: replace only the entries present in `patches`. */
    static void replaceClassesInJar(File inputJar, File outputJar,
                                     Map<String, byte[]> patches) throws IOException {
        try (ZipInputStream zin = new ZipInputStream(new FileInputStream(inputJar));
             ZipOutputStream zout = new ZipOutputStream(new FileOutputStream(outputJar))) {
            ZipEntry e;
            byte[] buf = new byte[65536];
            while ((e = zin.getNextEntry()) != null) {
                byte[] replacement = patches.get(e.getName());
                ZipEntry out = new ZipEntry(e.getName());
                out.setTime(e.getTime());
                zout.putNextEntry(out);
                if (replacement != null) {
                    zout.write(replacement);
                } else {
                    int len;
                    while ((len = zin.read(buf)) > 0) zout.write(buf, 0, len);
                }
                zout.closeEntry();
                zin.closeEntry();
            }
        }
    }

    private static void record(String label, int count) {
        summary.put(label, new int[]{count});
    }

    private static void printSummary() {
        int totalMethods = 0;
        int totalClasses = 0;
        System.err.println();
        System.err.println("=== Patch Summary ===");
        for (Map.Entry<String, int[]> e : summary.entrySet()) {
            int n = e.getValue()[0];
            System.err.printf("  %-35s %d method(s)%n", e.getKey(), n);
            totalMethods += n;
            if (n > 0) totalClasses++;
        }
        System.err.println("  ---");
        System.err.printf("  TOTAL: %d methods in %d classes%n", totalMethods, totalClasses);
        System.err.println();
    }
}
