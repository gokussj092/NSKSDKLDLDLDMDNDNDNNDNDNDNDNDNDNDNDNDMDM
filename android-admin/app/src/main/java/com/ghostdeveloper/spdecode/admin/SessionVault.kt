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

/** Only the expiring server session is persisted; passwords are never saved. */
internal class SessionVault(context: Context) {
  private val preferences = context.getSharedPreferences("admin-session", Context.MODE_PRIVATE)
  private val alias = "spdecode.admin.session.v1"

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

  fun save(value: String) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
    val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
    check(
        preferences
            .edit()
            .putString("session", Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP))
            .commit())
  }

  fun restore(): String? =
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

  fun clear() {
    preferences.edit().clear().commit()
  }
}
