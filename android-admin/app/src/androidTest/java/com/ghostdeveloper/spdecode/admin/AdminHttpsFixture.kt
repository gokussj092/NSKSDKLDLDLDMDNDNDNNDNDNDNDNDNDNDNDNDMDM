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
                """{"principal":{"id":"fixture_owner","name":"Operador de integración","username":"fixture.owner","role":"owner","capabilities":["users.read","staff.read","billing.read","support.read","audit.read"]}}"""
            "/api/admin/users" ->
                """{"count":1,"page":0,"pageSize":30,"users":[{"id":"fixture_account_001","name":"Usuario recibido por HTTPS","email":"fixture@example.invalid"}]}"""
            else -> "{}"
          }
      return ByteArrayInputStream(value.toByteArray(Charsets.UTF_8))
    }
  }
}
