package com.ghostdeveloper.spdecode.cloud;

/** Preserve original PNG bytes; only sample the bitmap used for display. */
public final class ServerVpnIconPolicy {
    // Same general response budget as the existing native HTTPS transport.
    public static final int CACHE_RECORD_BYTES = 6 * 1024 * 1024;
    public static final int DISPLAY_EDGE = 512;
    private static final byte[] PNG = {
        (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
    };

    private ServerVpnIconPolicy() {}

    public static boolean isPng(byte[] data) {
        if (data == null || data.length < 32) return false;
        for (int i = 0; i < PNG.length; i++) {
            if (data[i] != PNG[i]) return false;
        }
        return true;
    }

    /** Power-of-two sampling also handles large dimensions without overflow. */
    public static int sampleSize(int width, int height) {
        if (width <= 0 || height <= 0) throw new IllegalArgumentException("Invalid PNG bounds");
        int sample = 1;
        while (((long) width + sample - 1) / sample > DISPLAY_EDGE ||
               ((long) height + sample - 1) / sample > DISPLAY_EDGE) {
            sample *= 2;
        }
        return sample;
    }
}
