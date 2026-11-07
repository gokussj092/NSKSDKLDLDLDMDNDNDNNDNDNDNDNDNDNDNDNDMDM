// SP-DECODE F7-A5 Ghidra 12.1.4 headless: bounded symbol evidence only.
// Never execute the target program or export its code/strings/passwords.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class SpDecodeGhidraReport extends GhidraScript {
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9_.$]{1,100}");
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("NO_PROGRAM");
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("OUTPUT_REQUIRED");
        int count = currentProgram.getFunctionManager().getFunctionCount();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        StringBuilder json = new StringBuilder(4096);
        json.append("{\"functions\":").append(count);
        json.append(",\"candidateFunctions\":[");
        int enumerated=0;
        int emitted=0;
        while (iter.hasNext() && enumerated < 500000) {
            Function fun = iter.next();
            enumerated++;
            if (emitted >= 48) continue;
            String name=fun.getName();
            String lower=name.toLowerCase();
            if (!SAFE.matcher(name).matches()) continue;
            if (!(name.startsWith("Java_") || name.startsWith("JNI_")
                  || name.startsWith("EVP_") || name.startsWith("AES_")
                  || name.startsWith("crypto_") || lower.contains("decrypt")
                  || lower.contains("encrypt") || lower.contains("hysteria")
                  || lower.contains("chacha") || lower.contains("config"))) continue;
            String address=fun.getEntryPoint().toString();
            if (!address.matches("[0-9a-fA-F]{1,16}"))continue;
            if (emitted++ > 0)json.append(",");
            json.append("{\"name\":\"").append(name)
                .append("\",\"address\":\"").append(address).append("\"}");
        }
        json.append("],\"symbolsSampled\":").append(enumerated);
        json.append(",\"evidence\":\"SYMBOL_NAMES_ONLY_NOT_CRYPTO_PROOF\"}");
        Files.writeString(Path.of(args[0]),json.toString(),StandardCharsets.UTF_8);
    }
}
