package com.ghostdeveloper.spdecode.admin

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.json.JSONObject

/** Networking and the fixed origin/route allowlist are implemented in C++. */
internal class AdminApi(private val vault: SessionVault) {
  private val mutex = Mutex()
  // Connection data (origin, cookie path, session cookie names) lives in native
  // C++ and is exposed only through JNI. Kotlin never hardcodes it.
  private val origin = NativeAdminRoutes.originNative().toHttpUrl()
  private val cookiePath = NativeAdminRoutes.cookiePathNative()
  private val initialSession = vault.restoreSession()
  private var session: Cookie? = initialSession?.cookie?.let { Cookie.parse(origin, it) }

  /** True when this device had a stored session at startup (the user had logged in). */
  val hadStoredSession: Boolean = initialSession != null

  class Failure(val code: String, val http: Int = 0) : Exception(code)

  suspend fun clear() =
      mutex.withLock {
        session = null
        vault.clear()
      }

  suspend fun call(
      operation: String,
      query: String = "",
      page: Int = 0,
      input: JSONObject? = null
  ): JSONObject =
      withContext(Dispatchers.IO) {
        mutex.withLock {
          // Client-side session lifetime: 90 days from login. A specific code
          // lets the UI explain it instead of showing a generic expiry.
          if (operation != "login" && vault.isExpired90Days()) {
            session = null
            vault.clear()
            throw Failure("SESSION_EXPIRED_90D", 401)
          }
          val token = session?.takeIf { it.expiresAt > System.currentTimeMillis() }
          if (operation != "login" && token == null) {
            session = null
            vault.clear()
            throw Failure("UNAUTHORIZED", 401)
          }
          val body = input?.toString()?.toByteArray(Charsets.UTF_8) ?: byteArrayOf()
          val cookie =
              if (operation == "login") byteArrayOf()
              else "${token!!.name}=${token.value}".toByteArray(Charsets.UTF_8)
          try {
            val response =
                NativeAdminRoutes.exchangeNative(
                    operation.toByteArray(), query.toByteArray(Charsets.UTF_8), page, body, cookie)
            if (response.size != 3) throw Failure("INVALID_RESPONSE")
            val http = response[0].toString(Charsets.UTF_8).toIntOrNull() ?: 0
            val text = response[1].toString(Charsets.UTF_8)
            if (http == 0)
                throw Failure(text.takeIf { it.matches(Regex("[A-Z_]+")) } ?: "NETWORK_ERROR")
            if (http == 401 && operation != "login") {
              session = null
              vault.clear()
            }
            val json =
                runCatching { JSONObject(text) }
                    .getOrElse {
                      throw Failure(
                          if (http == 404) "SERVER_UPDATE_REQUIRED" else "INVALID_RESPONSE", http)
                    }
            if (http !in 200..299 || json.has("error") || json.optString("status") == "error") {
              val code =
                  json.optJSONObject("error")?.optString("code")
                      ?: json.optString("code").takeIf { it.isNotEmpty() }
                      ?: "HTTP_ERROR"
              throw Failure(code, http)
            }
            if (operation == "login") {
              val required =
                  if (json.optBoolean("staff")) NativeAdminRoutes.sessionCookieNameNative(true)
                  else if (json.optString("role") == "owner") NativeAdminRoutes.sessionCookieNameNative(false)
                  else throw Failure("INVALID_RESPONSE")
              val valid =
                  response[2]
                      .toString(Charsets.UTF_8)
                      .lineSequence()
                      .mapNotNull { Cookie.parse(origin, it) }
                      .filter {
                        it.name == required &&
                            it.secure &&
                            it.httpOnly &&
                            it.hostOnly &&
                            it.domain == origin.host &&
                            it.path == cookiePath &&
                            it.expiresAt > System.currentTimeMillis() &&
                            it.value.isNotEmpty()
                      }
                      .toList()
              session = valid.singleOrNull() ?: throw Failure("SESSION_COOKIE_MISSING")
              vault.save(session.toString())
            }
            if (operation == "logout") {
              session = null
              vault.clear()
            }
            json
          } finally {
            body.fill(0)
            cookie.fill(0)
          }
        }
      }
}
