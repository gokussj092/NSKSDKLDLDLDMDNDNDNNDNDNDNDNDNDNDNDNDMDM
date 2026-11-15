package com.ghostdeveloper.spdecode.admin

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

/** Only the expiring server session is persisted; passwords are never saved. */
internal class SessionVault(context: Context) {
  private val preferences = context.getSharedPreferences("admin-session", Context.MODE_PRIVATE)
  private val alias = "spdecode.admin.session.v1"

  companion object {
    /** Client-side session lifetime: 90 days from login. */
    const val SESSION_LIFETIME_DAYS = 90L
    const val SESSION_LIFETIME_MILLIS = SESSION_LIFETIME_DAYS * 24 * 60 * 60 * 1000
  }

  /** A stored session: the server cookie plus the login moment (null for legacy entries). */
  internal data class StoredSession(val cookie: String, val loginAt: Long?)

  private fun key(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return (store.getKey(alias, null) as? SecretKey)
        ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
          init(
              KeyGenParameterSpec.Builder(
                      alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                  .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                  .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                  .setRandomizedEncryptionRequired(true)
                  .build())
          generateKey()
        }
  }

  private fun encrypt(plain: String) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
    val encrypted = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
    check(
        preferences
            .edit()
            .putString("session", Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP))
            .commit())
  }

  private fun decrypt(): String? =
      runCatching {
            val stored = preferences.getString("session", null) ?: return null
            val data = Base64.decode(stored, Base64.NO_WRAP)
            require(data.size in 29..8192)
            val cipher =
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                  init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, data.copyOfRange(0, 12)))
                }
            cipher.doFinal(data.copyOfRange(12, data.size)).toString(Charsets.UTF_8)
          }
          .getOrElse {
            clear()
            null
          }

  /** Saves the session cookie stamped with the login moment (now). */
  fun save(value: String) {
    saveSession(value, System.currentTimeMillis())
  }

  fun saveSession(value: String, loginAtMillis: Long) {
    encrypt(JSONObject().put("cookie", value).put("loginAt", loginAtMillis).toString())
  }

  /** Restores the stored session, or null. Legacy entries (bare cookie) get loginAt = null. */
  fun restoreSession(): StoredSession? {
    val text = decrypt() ?: return null
    if (!text.trimStart().startsWith("{")) return StoredSession(text, null)
    val json = runCatching { JSONObject(text) }.getOrNull() ?: return StoredSession(text, null)
    val cookie = json.optString("cookie").takeIf { it.isNotEmpty() } ?: return null
    val loginAt = json.optLong("loginAt").takeIf { it > 0 }
    return StoredSession(cookie, loginAt)
  }

  fun restore(): String? = restoreSession()?.cookie

  /** True only when the stored login is older than 90 days. Unknown age never expires here. */
  fun isExpired90Days(now: Long = System.currentTimeMillis()): Boolean {
    val loginAt = restoreSession()?.loginAt ?: return false
    return now - loginAt >= SESSION_LIFETIME_MILLIS
  }

  fun clear() {
    preferences.edit().clear().commit()
  }
}
