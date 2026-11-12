package com.ghostdeveloper.spdecode

import androidx.compose.runtime.Composable

/** Compatibility entry point: every result now uses the same continuous viewer. */
@Composable
internal fun JsonTreeViewer(
    raw: String,
    suffix: String,
    maskCredentials: Boolean,
    identity: String,
) {
    LargeResultViewer(raw, maskCredentials, identity, suffix)
}
