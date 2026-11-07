// Ghidra 11+ headless post-analysis evidence. No app code executed.
import ghidra.app.script.GhidraScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class SpDecodeGhidraReport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("No program");
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Report path missing");
        int count = currentProgram.getFunctionManager().getFunctionCount();
        String json = "{\"functions\":" + count + ",\"source\":\"GHIDRA_HEADLESS_STATIC\"}";
        Files.writeString(Path.of(args[0]), json, StandardCharsets.UTF_8);
    }
}
