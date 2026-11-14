package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

internal val Rounded = RoundedCornerShape(16.dp)

@Composable
internal fun Small(value: String, modifier: Modifier = Modifier, color: Color = Muted) {
    Text(value, modifier, color, fontSize = 12.sp)
}

@Composable
internal fun Tile(
    modifier: Modifier = Modifier,
    color: Color = Panel,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier.clip(Rounded).background(color).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp),
        content = content,
    )
}

@Composable
internal fun Avatar(icon: ImageVector, tint: Color = Mint, size: Int = 44) {
    Box(
        Modifier.size(size.dp)
            .background(tint.copy(alpha = .13f), RoundedCornerShape((size * .28).dp)),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, null, Modifier.size((size * .5).dp), tint)
    }
}

@Composable
internal fun statusColor(status: String): Color =
    when (status) {
        "Suspendido",
        "Revocada",
        "Reembolsado" -> Red
        "Premium",
        "Pendiente" -> Amber
        else -> Mint
    }

@Composable
internal fun UserAvatar(user: PreviewUser, size: Int = 46) {
    val tint = statusColor(user.status)
    Box(
        Modifier.size(size.dp).background(tint.copy(alpha = .18f), CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            user.initials,
            color = tint,
            fontSize = (size * .33).sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
internal fun ScreenList(content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        LazyColumn(
            Modifier.widthIn(max = 840.dp).fillMaxSize().testTag("screen-list"),
            contentPadding = PaddingValues(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            content = content,
        )
    }
}

@Composable
internal fun Metric(
    label: String,
    value: String,
    icon: ImageVector,
    tint: Color = Mint,
    modifier: Modifier = Modifier,
) {
    Tile(modifier) {
        Icon(icon, null, Modifier.size(21.dp), tint)
        Text(value, color = Ink, fontWeight = FontWeight.SemiBold, fontSize = 26.sp)
        Text(label, color = Muted, fontSize = 13.sp)
    }
}

@Composable
internal fun Trend(
    values: List<Float> = listOf(.84f, .68f, .74f, .44f, .57f, .32f, .45f, .16f, .26f, .06f)
) {
    val border = Border
    val mint = Mint
    Canvas(Modifier.fillMaxWidth().height(120.dp)) {
        repeat(4) {
            val y = size.height * it / 3
            drawLine(border, Offset(0f, y), Offset(size.width, y))
        }
        val line = Path()
        values.forEachIndexed { i, y ->
            val x = size.width * i / (values.size - 1)
            if (i == 0) line.moveTo(x, size.height * y) else line.lineTo(x, size.height * y)
        }
        val fill =
            Path().apply {
                addPath(line)
                lineTo(size.width, size.height)
                lineTo(0f, size.height)
                close()
            }
        drawPath(fill, mint.copy(alpha = .09f))
        drawPath(line, mint, style = androidx.compose.ui.graphics.drawscope.Stroke(2.5.dp.toPx()))
    }
}

@Composable
internal fun fieldColors() =
    TextFieldDefaults.colors(
        focusedContainerColor = Panel,
        unfocusedContainerColor = Panel,
        focusedIndicatorColor = Color.Transparent,
        unfocusedIndicatorColor = Color.Transparent,
        cursorColor = Mint,
    )

@Composable
internal fun SearchField(
    query: String,
    change: (String) -> Unit,
    placeholder: String,
    trailing: @Composable (() -> Unit)? = null,
) {
    TextField(
        query,
        { change(it.take(100)) },
        placeholder = { Text(placeholder, fontSize = 14.sp) },
        leadingIcon = { Icon(Icons.Outlined.Search, null, Modifier.size(21.dp)) },
        trailingIcon = trailing,
        singleLine = true,
        shape = CircleShape,
        colors = fieldColors(),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
internal fun FilterRow(labels: List<String>, selected: String, onSelect: (String) -> Unit) {
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        labels.forEach { label ->
            FilterChip(
                selected == label,
                { onSelect(label) },
                { Text(label, fontSize = 13.sp) },
                shape = CircleShape,
                border = null,
                colors =
                    FilterChipDefaults.filterChipColors(
                        selectedContainerColor = GreenPanel,
                        selectedLabelColor = Mint,
                    ),
            )
        }
    }
}

@Composable
internal fun EditorField(
    label: String,
    value: String,
    change: (String) -> Unit,
    keyboard: KeyboardType = KeyboardType.Text,
    max: Int = 160,
    lines: Int = 1,
) {
    OutlinedTextField(
        value,
        { change(it.take(max)) },
        label = { Text(label) },
        singleLine = lines == 1,
        minLines = if (lines == 1) 1 else 3,
        maxLines = lines,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        shape = Rounded,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
internal fun EmptyState(
    title: String,
    description: String,
    icon: ImageVector = Icons.Outlined.SearchOff,
) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 36.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Avatar(icon, Muted, 60)
        Text(title, color = Ink, fontWeight = FontWeight.SemiBold)
        Text(description, color = Muted, fontSize = 13.sp, textAlign = TextAlign.Center)
    }
}

@Composable
internal fun ActionRow(
    label: String,
    icon: ImageVector,
    detail: String? = null,
    onClick: () -> Unit,
) {
    Column {
        Row(
            Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 15.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            Icon(icon, null, Modifier.size(21.dp), Mint)
            Column(Modifier.weight(1f)) {
                Text(label, color = Ink, fontSize = 15.sp)
                if (detail != null) Small(detail)
            }
            Icon(Icons.Outlined.ChevronRight, null, tint = Muted)
        }
        HorizontalDivider(color = Border)
    }
}

@Composable
internal fun PrimaryAction(label: String, enabled: Boolean = true, onClick: () -> Unit) {
    Button(
        onClick,
        enabled = enabled,
        shape = Rounded,
        modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
    ) {
        Text(label, fontWeight = FontWeight.Medium)
    }
}

@Composable
internal fun SecondaryAction(label: String, danger: Boolean = false, onClick: () -> Unit) {
    FilledTonalButton(
        onClick,
        shape = Rounded,
        colors =
            ButtonDefaults.filledTonalButtonColors(
                containerColor = if (danger) Red.copy(alpha = .13f) else GreenPanel,
                contentColor = if (danger) Red else Mint,
            ),
        modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
    ) {
        Text(label)
    }
}

@Composable
internal fun ConfirmationDialog(
    title: String,
    text: String,
    confirm: String = "Confirmar",
    danger: Boolean = false,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        icon = {
            Icon(
                if (danger) Icons.Outlined.WarningAmber else Icons.Outlined.Info,
                null,
                tint = if (danger) Red else Mint,
            )
        },
        title = { Text(title) },
        text = { Text(text, color = Muted) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(confirm, color = if (danger) Red else Mint) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
internal fun FormDialog(
    title: String,
    valid: Boolean,
    confirm: String = "Guardar",
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = Panel,
        title = { Text(title, fontSize = 20.sp, fontWeight = FontWeight.SemiBold) },
        text = {
            Column(
                Modifier.heightIn(max = 460.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                content = content,
            )
        },
        confirmButton = { TextButton(onClick = onConfirm, enabled = valid) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
internal fun <T> SelectField(
    label: String,
    value: T,
    options: List<T>,
    text: (T) -> String,
    onSelect: (T) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
        Small(label)
        Box {
            Row(
                Modifier.fillMaxWidth()
                    .clip(Rounded)
                    .background(Panel)
                    .clickable { open = true }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(text(value), Modifier.weight(1f), color = Ink, fontSize = 14.sp)
                Icon(Icons.Outlined.ExpandMore, "Elegir $label", tint = Muted)
            }
            DropdownMenu(
                open,
                { open = false },
                containerColor = Panel,
                modifier = Modifier.heightIn(max = 340.dp),
            ) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(text(option), fontSize = 14.sp) },
                        onClick = {
                            onSelect(option)
                            open = false
                        },
                    )
                }
            }
        }
    }
}

@Composable
internal fun CountBadge(count: Int) {
    if (count > 0)
        Box(
            Modifier.sizeIn(minWidth = 22.dp, minHeight = 22.dp)
                .background(Mint, CircleShape)
                .padding(horizontal = 6.dp, vertical = 2.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(count.toString(), color = MaterialTheme.colorScheme.onPrimary, fontSize = 12.sp)
        }
}

@Composable
internal fun PreviewBanner() {
    Row(
        Modifier.fillMaxWidth()
            .background(Amber.copy(alpha = .08f))
            .padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Outlined.Science, null, Modifier.size(13.dp), Amber)
        Spacer(Modifier.width(6.dp))
        Text("Vista previa · datos de prueba · sin conexión", color = Amber, fontSize = 10.sp)
    }
}

@Composable
internal fun rememberCopyToClipboard(): (String) -> Unit {
    val context = androidx.compose.ui.platform.LocalContext.current
    return remember(context) {
        { text: String ->
            context
                .getSystemService(android.content.ClipboardManager::class.java)
                .setPrimaryClip(android.content.ClipData.newPlainText("SP-DECODE", text))
        }
    }
}
