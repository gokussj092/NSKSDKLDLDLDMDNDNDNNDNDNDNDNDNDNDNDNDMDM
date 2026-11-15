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
  private val origin = "https://panel.spdecode.xyz".toHttpUrl()
  private var session: Cookie? = vault.restore()?.let { Cookie.parse(origin, it) }

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
                  if (json.optBoolean("staff")) "spdecode_staff_session"
                  else if (json.optString("role") == "owner") "spdecode_admin_session"
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
                            it.path == "/api/admin" &&
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
