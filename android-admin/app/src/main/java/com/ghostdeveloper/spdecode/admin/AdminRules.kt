package com.ghostdeveloper.spdecode.admin

import java.math.BigDecimal
import java.net.InetAddress
import java.util.Locale

internal fun money(cents: Long): String =
    "$" + BigDecimal.valueOf(cents, 2).setScale(2).toPlainString()

internal fun parsePrice(value: String): Long? =
    runCatching {
          val text = value.trim().replace(',', '.')
          require(text.matches(Regex("[0-9]{1,5}(\\.[0-9]{1,2})?")))
          BigDecimal(text).movePointRight(2).longValueExact().also { require(it in 1..9_999_999) }
        }
        .getOrNull()

internal fun canonicalIp(value: String): String? {
  val text = value.trim()
  if (text.length !in 3..45) return null
  if (':' in text) {
    if (!text.matches(Regex("[a-fA-F0-9:.]+"))) return null
    return runCatching { InetAddress.getByName(text).hostAddress?.lowercase(Locale.ROOT) }
        .getOrNull()
  }
  val parts = text.split('.')
  if (parts.size != 4 ||
      parts.any { !it.matches(Regex("0|[1-9][0-9]{0,2}")) || (it.toIntOrNull() ?: 999) > 255 })
      return null
  return parts.joinToString(".")
}

internal fun csvCell(value: String): String {
  val safe =
      if (value.trimStart().firstOrNull() in listOf('=', '+', '-', '@', '\t', '\r')) "'$value"
      else value
  return "\"" + safe.replace("\"", "\"\"") + "\""
}

internal enum class Appearance {
  Amoled,
  Dark,
  Light
}

internal fun shouldFollowNewMessages(previousCount: Int, lastVisible: Int): Boolean =
    previousCount == 0 || (lastVisible >= 0 && lastVisible >= previousCount - 2)
