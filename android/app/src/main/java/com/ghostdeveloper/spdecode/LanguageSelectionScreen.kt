package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowBack
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val languageFlags=mapOf(
    "es" to "🇪🇸",
    "en" to "🇬🇧",
    "pt-BR" to "🇧🇷",
    "ar" to "🇸🇦",
    "fa" to "🇮🇷",
    "fr" to "🇫🇷",
    "id" to "🇮🇩",
    "ru" to "🇷🇺",
    "de" to "🇩🇪",
    "tr" to "🇹🇷",
    "vi" to "🇻🇳",
    "hi" to "🇮🇳",
    "ja" to "🇯🇵",
    "it" to "🇮🇹"
)
private val LanguageAccent=Color(0xFFAE8AE6)
private val LanguageText=Color(0xFFF7F7F7)
private val LanguageSecondary=Color(0xFFABABAB)

/** Dedicated settings destination; parent keeps persistent app bottom tabs. */
@Composable
internal fun LanguageSelectionScreen(
    selectedLanguage:String,
    onBack:()->Unit,
    onSelect:(String)->Unit,
) {
    Column(
        Modifier.fillMaxSize().background(Color.Black)
            .testTag("settings_language_screen")
            .padding(horizontal=20.dp,vertical=12.dp),
        verticalArrangement=Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment=Alignment.CenterVertically) {
            IconButton(onClick=onBack,modifier=Modifier.size(44.dp)
                .testTag("settings_language_back")) {
                Icon(Icons.Outlined.ArrowBack,
                    contentDescription=stringResource(R.string.close),
                    tint=LanguageText,modifier=Modifier.size(25.dp))
            }
            Spacer(Modifier.width(6.dp))
            Text(stringResource(R.string.language_screen_title),
                color=LanguageText,fontSize=24.sp,fontWeight=FontWeight.Bold,
                modifier=Modifier.weight(1f))
        }
        Text(stringResource(R.string.language_pick_description),
            color=LanguageSecondary,fontSize=13.sp,lineHeight=19.sp)
        LazyColumn(
            modifier=Modifier.fillMaxSize(),
            contentPadding=PaddingValues(bottom=20.dp),
            verticalArrangement=Arrangement.spacedBy(8.dp),
        ) {
            items(SupportedLanguages.options,key={it.tag}) { option ->
                val selected=selectedLanguage==option.tag
                val optionTitle=if(option.tag=="system")
                    stringResource(R.string.language_system)
                    else option.nativeName
                Surface(
                    color=if(selected)Color(0xFF272034) else Color(0xFF242424),
                    border=BorderStroke(1.dp,
                        if(selected)LanguageAccent else Color(0xFF343434)),
                    shape=RoundedCornerShape(16.dp),
                    modifier=Modifier.fillMaxWidth()
                        .testTag("language_option_${option.tag}")
                        .clickable { if(!selected)onSelect(option.tag) },
                ) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=8.dp),
                        verticalAlignment=Alignment.CenterVertically,
                        horizontalArrangement=Arrangement.spacedBy(13.dp),
                    ) {
                        Surface(
                            modifier=Modifier.size(43.dp),
                            color=Color(0xFF303030),
                            shape=RoundedCornerShape(11.dp),
                        ) {
                            Box(contentAlignment=Alignment.Center) {
                                if(option.tag=="system") {
                                    Icon(Icons.Outlined.Language,null,
                                        tint=LanguageText,modifier=Modifier.size(24.dp))
                                }else{
                                    Text(languageFlags[option.tag].orEmpty(),
                                        fontSize=26.sp)
                                }
                            }
                        }
                        Text(optionTitle,
                            color=LanguageText,
                            fontSize=16.sp,
                            fontWeight=if(selected)FontWeight.SemiBold else FontWeight.Normal,
                            maxLines=1,overflow=TextOverflow.Ellipsis,
                            modifier=Modifier.weight(1f))
                        RadioButton(
                            selected=selected,
                            onClick={if(!selected)onSelect(option.tag)},
                            colors=RadioButtonDefaults.colors(
                                selectedColor=LanguageAccent,
                                unselectedColor=LanguageSecondary),
                            modifier=Modifier.size(40.dp),
                        )
                    }
                }
            }
        }
    }
}
