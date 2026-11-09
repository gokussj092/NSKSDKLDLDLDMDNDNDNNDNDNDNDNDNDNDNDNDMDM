// Static native method evidence from pinned Ghidra; never execute the target.
// Generated C remains private: export only hashes, coordinates and safe names.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.TreeSet;
import java.util.regex.Pattern;

public class SpDecodeGhidraReport extends GhidraScript {
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9_.$]{1,160}");
    private static boolean interesting(String name) {
        if (!SAFE.matcher(name).matches()) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        return name.startsWith("Java_") || name.startsWith("JNI_")
            || name.startsWith("EVP_") || name.startsWith("AES_")
            || name.startsWith("crypto_") || lower.contains("decrypt")
            || lower.contains("encrypt") || lower.contains("hysteria")
            || lower.contains("chacha") || lower.contains("config");
    }
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("NO_PROGRAM");
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("OUTPUT_REQUIRED");
        int count = currentProgram.getFunctionManager().getFunctionCount();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder json = new StringBuilder(8192);
        json.append("{\"functions\":").append(count);
        json.append(",\"candidateFunctions\":[");
        int enumerated = 0, emitted = 0, attempted = 0;
        DecompInterface decompiler = new DecompInterface();
        try {
            boolean ready = decompiler.openProgram(currentProgram);
            while (iter.hasNext() && enumerated < 500000 && !monitor.isCancelled()) {
                Function fun = iter.next();
                enumerated++;
                if (emitted >= 48) continue;
                String name = fun.getName();
                if (!interesting(name)) continue;
                String address = fun.getEntryPoint().toString();
                if (!address.matches("[0-9a-fA-F]{1,16}")) continue;
                if (emitted++ > 0) json.append(",");
                json.append("{\"name\":\"").append(name)
                    .append("\",\"address\":\"").append(address).append("\"");
                boolean completed = false;
                if (ready && !fun.isExternal() && !fun.isThunk() && attempted < 12) {
                    attempted++;
                    DecompileResults result = decompiler.decompileFunction(fun, 5, monitor);
                    if (result != null && result.decompileCompleted()
                            && result.getDecompiledFunction() != null) {
                        String source = result.getDecompiledFunction().getC();
                        if (source != null && !source.isEmpty()) {
                            String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                                .digest(source.getBytes(StandardCharsets.UTF_8)));
                            json.append(",\"decompiledCSha256\":\"").append(hash).append("\"");
                            json.append(",\"decompiledCLines\":").append(source.lines().count());
                            completed = true;
                        }
                    }
                }
                json.append(",\"decompilationCompleted\":").append(completed);
                TreeSet<String> calls = new TreeSet<>();
                for (Function callee : fun.getCalledFunctions(monitor)) {
                    String target = callee.getName();
                    if (interesting(target) && calls.size() < 16) calls.add(target);
                }
                json.append(",\"calledCryptoFunctions\":[");
                int n = 0;
                for (String target : calls) {
                    if (n++ > 0) json.append(",");
                    json.append("\"").append(target).append("\"");
                }
                json.append("],\"methodValidated\":false}");
            }
        } finally {
            decompiler.dispose();
        }
        json.append("],\"symbolsSampled\":").append(enumerated);
        json.append(",\"decompilationAttempts\":").append(attempted);
        json.append(",\"evidence\":\"STATIC_NATIVE_METHOD_CANDIDATES\"");
        json.append(",\"rawSourceExported\":false,\"codeExecuted\":false,\"methodValidated\":false}");
        Files.writeString(Path.of(args[0]), json.toString(), StandardCharsets.UTF_8);
    }
}
