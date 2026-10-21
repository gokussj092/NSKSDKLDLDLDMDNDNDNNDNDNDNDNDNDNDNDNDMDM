package com.ghostdeveloper.spdecode

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/**
 * One color scheme for the entire Activity, including modal dialogs rendered
 * outside SpDecodeApp (legal consent, protected file and Cloud password).
 * Pure AMOLED black, readable white text and neutral—not default purple—actions.
 */
internal object SpDecodeAmoledColors {
    val background=Color(0xFF000000)
    val panel=Color(0xFF242424)
    val text=Color(0xFFF7F7F7)
    val muted=Color(0xFFABABAB)
}

private val Scheme=darkColorScheme(
    primary=SpDecodeAmoledColors.text,
    onPrimary=SpDecodeAmoledColors.background,
    primaryContainer=SpDecodeAmoledColors.panel,
    onPrimaryContainer=SpDecodeAmoledColors.text,
    secondary=SpDecodeAmoledColors.text,
    onSecondary=SpDecodeAmoledColors.background,
    tertiary=SpDecodeAmoledColors.text,
    onTertiary=SpDecodeAmoledColors.background,
    background=SpDecodeAmoledColors.background,
    onBackground=SpDecodeAmoledColors.text,
    surface=SpDecodeAmoledColors.background,
    onSurface=SpDecodeAmoledColors.text,
    surfaceVariant=SpDecodeAmoledColors.panel,
    onSurfaceVariant=SpDecodeAmoledColors.muted,
    outline=Color(0xFF525252),
)

@Composable
internal fun SpDecodeAmoledTheme(content:@Composable ()->Unit) {
    MaterialTheme(colorScheme=Scheme,content=content)
}
