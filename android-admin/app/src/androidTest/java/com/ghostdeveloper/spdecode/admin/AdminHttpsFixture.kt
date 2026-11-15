package com.ghostdeveloper.spdecode.admin

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URL
import java.net.URLConnection
import java.net.URLStreamHandler
import java.security.cert.Certificate
import java.util.Collections
import javax.net.ssl.HttpsURLConnection

/** Instrumentation-only HTTPS peer. No fixtures or transport switch ship in the app. */
internal object AdminHttpsFixture {
  val paths: MutableList<String> = Collections.synchronizedList(mutableListOf())
  private var ticketStatus = "open"
  private val messages = org.json.JSONArray().put(org.json.JSONObject()
      .put("id", "message_1").put("sender", "user").put("text", "Mensaje de integración")
      .put("at", "2026-11-14T12:00:00Z"))

  fun install() {
    URL.setURLStreamHandlerFactory { protocol ->
      if (protocol == "https")
          object : URLStreamHandler() {
            override fun openConnection(url: URL): URLConnection = Peer(url)
          }
      else null
    }
  }

  private class Peer(url: URL) : HttpsURLConnection(url) {
    private val body = ByteArrayOutputStream()

    override fun connect() {}

    override fun disconnect() {}

    override fun usingProxy() = false

    override fun getCipherSuite() = "TLS_INSTRUMENTATION_FIXTURE"

    override fun getLocalCertificates(): Array<Certificate>? = null

    override fun getServerCertificates(): Array<Certificate>? = null

    override fun getOutputStream(): OutputStream = body

    override fun getResponseCode(): Int {
      check(url.host == "panel.spdecode.xyz")
      if (url.path == "/api/admin/login" || url.path == "/api/admin/logout") {
        check(requestMethod == "POST")
        check(getRequestProperty("Origin") == "https://panel.spdecode.xyz")
        check(getRequestProperty("X-SPDECODE-ADMIN-ACTION") == "1")
      }
      if (url.path != "/api/admin/login")
          check(getRequestProperty("Cookie") == "spdecode_admin_session=fixture.token")
      paths.add(url.path)
      return 200
    }

    override fun getHeaderFieldKey(index: Int): String? =
        if (index == 1 && url.path == "/api/admin/login") "Set-Cookie" else null

    override fun getHeaderField(index: Int): String? =
        if (index == 1)
            "spdecode_admin_session=fixture.token; Secure; HttpOnly; Path=/api/admin; Max-Age=1800"
        else null

    override fun getInputStream(): InputStream {
      val value =
          when (url.path) {
            "/api/admin/login" -> """{"role":"owner"}"""
            "/api/admin/access" ->
                """{"principal":{"id":"fixture_owner","name":"Operador de integración","username":"fixture.owner","role":"owner","capabilities":["users.read","staff.read","billing.read","support.read","support.write","support.assign","audit.read"]}}"""
            "/api/admin/users" ->
                if (url.query?.startsWith("id=") == true)
                  """{"user":{"id":"fixture_account_001","name":"Usuario recibido por HTTPS","username":"fixture.user","email":"fixture@example.invalid","email_verified":true},"identities":[],"orders":[],"entitlements":[],"redemptions":[],"tickets":[],"sessions":{"total":1},"creditMovements":[]}"""
                else """{"count":1,"page":0,"pageSize":30,"users":[{"id":"fixture_account_001","name":"Usuario recibido por HTTPS","username":"fixture.user","email":"fixture@example.invalid","email_verified":true}]}"""
            "/api/admin/support" -> synchronized(AdminHttpsFixture) {
              if (requestMethod == "POST") {
                val input = org.json.JSONObject(body.toString("UTF-8"))
                check(input.optString("threadId") == "fixture_ticket_001")
                when(input.optString("action")) {
                  "reply" -> {
                    messages.put(org.json.JSONObject().put("id", "message_" + (messages.length() + 1))
                        .put("sender", "admin").put("text", input.getString("message"))
                        .put("at", "2026-11-14T12:01:00Z")
                        .put("agent", org.json.JSONObject().put("name", "Operador de integración")))
                    ticketStatus = "answered"
                  }
                  "close" -> ticketStatus = "closed"
                  "reopen" -> ticketStatus = "open"
                }
                org.json.JSONObject().put("saved", true).put("status", ticketStatus).toString()
              } else org.json.JSONObject().put("threads", org.json.JSONArray().put(org.json.JSONObject()
                  .put("id", "fixture_ticket_001").put("name", "Usuario recibido por HTTPS")
                  .put("username", "fixture.user").put("subject", "Ticket de integración")
                  .put("status", ticketStatus).put("messages", messages)
                  .put("last_message_at", "2026-11-14T12:01:00Z"))).put("agents", org.json.JSONArray()).toString()
            }
            "/api/admin/mobile" -> """{"items":[],"count":0,"page":0,"pageSize":50,"live":false,"totals":[]}"""
            else -> "{}"
          }
      return ByteArrayInputStream(value.toByteArray(Charsets.UTF_8))
    }
  }
}
