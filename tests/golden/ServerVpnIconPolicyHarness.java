import java.lang.reflect.InvocationTargetException;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import javax.tools.ToolProvider;

/** Execute the production Android-independent policy, not a second implementation. */
class ServerVpnIconPolicyHarness {
    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Icon policy regression");
    }

    public static void main(String[] args) throws Exception {
        Path output = Path.of(args[2]);
        check(ToolProvider.getSystemJavaCompiler().run(null, null, null,
                "-d", output.toString(), args[0]) == 0);
        try (URLClassLoader loader = new URLClassLoader(new java.net.URL[]{output.toUri().toURL()})) {
            Class<?> policy = loader.loadClass("com.ghostdeveloper.spdecode.cloud.ServerVpnIconPolicy");
            var png = policy.getMethod("isPng", byte[].class);
            var sample = policy.getMethod("sampleSize", int.class, int.class);
            byte[] original = Files.readAllBytes(Path.of(args[1]));
            check(original.length > 256 * 1024);
            check((boolean) png.invoke(null, (Object) original));
            byte[] larger = Arrays.copyOf(original, 1024 * 1024 + 1);
            check((boolean) png.invoke(null, (Object) larger));
            check(!(boolean) png.invoke(null, (Object) null));
            check(!(boolean) png.invoke(null, (Object) new byte[31]));
            original[0] = 0;
            check(!(boolean) png.invoke(null, (Object) original));
            int[][] cases = {
                {1, 1, 1}, {512, 512, 1}, {513, 512, 2}, {720, 718, 2},
                {2048, 1024, 4}, {4097, 1, 16}, {16384, 8192, 32},
                {Integer.MAX_VALUE, Integer.MAX_VALUE, 4194304}
            };
            for (int[] item : cases) {
                int actual = (int) sample.invoke(null, item[0], item[1]);
                check(actual == item[2]);
                check(((long) item[0] + actual - 1) / actual <= 512);
                check(((long) item[1] + actual - 1) / actual <= 512);
            }
            for (int[] item : new int[][]{{0, 10}, {10, 0}, {-1, 10}}) {
                try {
                    sample.invoke(null, item[0], item[1]);
                    throw new AssertionError("Invalid bounds accepted");
                } catch (InvocationTargetException error) {
                    check(error.getCause() instanceof IllegalArgumentException);
                }
            }
            check(policy.getField("CACHE_RECORD_BYTES").getInt(null) == 6 * 1024 * 1024);
        }
        System.out.println("Original PNG accepted; display sampling and cache policy passed");
    }
}
