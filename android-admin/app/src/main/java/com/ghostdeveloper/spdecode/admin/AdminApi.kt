package com.ghostdeveloper.spdecode.admin

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/** Explicitly opt-in integration seam. The preview Activity never constructs this client. */
internal class AdminApi(origin: String) {
    private val base =
        origin.toHttpUrl().also {
            require(
                it.isHttps &&
                    it.port == 443 &&
                    it.encodedPath == "/" &&
                    it.query == null &&
                    it.fragment == null &&
                    it.username.isEmpty() &&
                    it.password.isEmpty()
            )
            require(
                origin == "https://${it.host}" &&
                    it.host.contains('.') &&
                    !it.host.matches(Regex("[0-9.]+"))
            )
        }
    private val client =
        OkHttpClient.Builder()
            .cookieJar(CookieJar.NO_COOKIES)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
    private val lock = Any()
    private var session: Cookie? = null
    private var mustChangePassword = false
    private val json = "application/json".toMediaType()
    private val readOps =
        setOf(
            "access",
            "session",
            "users",
            "user_detail",
            "staff",
            "roles",
            "audit",
            "support",
            "store",
            "gifts",
            "notifications",
            "observability",
            "reports",
        )

    class Failure(val code: String, val http: Int = 0) : IOException(code)

    suspend fun login(username: String, password: String): JSONObject =
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                clear()
                require(
                    username.isNotBlank() &&
                        username.length <= 128 &&
                        password.isNotEmpty() &&
                        password.length <= 512
                )
                val body =
                    JSONObject()
                        .put("username", username)
                        .put("password", password)
                        .toString()
                        .toByteArray(Charsets.UTF_8)
                try {
                    val result = exchange("login", body = body)
                    if (session == null) throw Failure("SESSION_COOKIE_MISSING")
                    mustChangePassword = result.optBoolean("mustChangePassword", false)
                    result
                } catch (e: Exception) {
                    clear()
                    throw e
                } finally {
                    body.fill(0)
                }
            }
        }

    suspend fun read(operation: String, query: String = "", page: Int = 0): JSONObject =
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                require(operation in readOps)
                if (mustChangePassword && operation !in setOf("access", "session"))
                    throw Failure("PASSWORD_CHANGE_REQUIRED")
                exchange(operation, query, page)
            }
        }

    suspend fun logout(): Unit =
        withContext(Dispatchers.IO) {
            synchronized(lock) {
                try {
                    if (session != null) exchange("logout", body = "{}".toByteArray())
                } finally {
                    clear()
                }
                Unit
            }
        }

    fun clearLocal() {
        synchronized(lock) { clear() }
    }

    private fun clear() {
        session = null
        mustChangePassword = false
    }

    private fun exchange(
        operation: String,
        query: String = "",
        page: Int = 0,
        body: ByteArray? = null,
    ): JSONObject {
        val plan = NativeAdminRoutes.plan(operation, query, page, body?.size ?: 0)
        val url = base.resolve(plan.path) ?: throw Failure("INVALID_ROUTE")
        if (
            url.host != base.host ||
                url.port != base.port ||
                !url.isHttps ||
                !url.encodedPath.startsWith("/api/admin/")
        )
            throw Failure("INVALID_ROUTE")
        val now = System.currentTimeMillis()
        val token = session?.takeIf { it.expiresAt > now && it.matches(url) }
        if (operation != "login" && token == null) {
            clear()
            throw Failure("UNAUTHORIZED", 401)
        }
        val req =
            Request.Builder()
                .url(url)
                .header("Accept", "application/json")
                .header("Cache-Control", "no-store")
        if (token != null) req.header("Cookie", token.name + "=" + token.value)
        if (plan.method == "POST")
            req.header("Origin", "https://${base.host}")
                .header("X-SPDECODE-ADMIN-ACTION", "1")
                .post(requireNotNull(body).toRequestBody(json))
        else req.get()
        try {
            client.newCall(req.build()).execute().use { response ->
                if (response.code == 401) {
                    clear()
                    throw Failure("UNAUTHORIZED", 401)
                }
                if (response.code in 300..399) throw Failure("REDIRECT_REJECTED", response.code)
                val rb = response.body ?: throw Failure("EMPTY_RESPONSE", response.code)
                if (rb.contentLength() > plan.maxResponse)
                    throw Failure("RESPONSE_TOO_LARGE", response.code)
                val data = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                rb.byteStream().use { input ->
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        if (data.size() + n > plan.maxResponse)
                            throw Failure("RESPONSE_TOO_LARGE", response.code)
                        data.write(buffer, 0, n)
                    }
                }
                val result =
                    try {
                        JSONObject(data.toString("UTF-8"))
                    } catch (_: Exception) {
                        throw Failure("INVALID_RESPONSE", response.code)
                    }
                val error =
                    result.optJSONObject("error")?.optString("code")?.takeIf {
                        it.matches(Regex("[A-Z0-9_]{1,80}"))
                    }
                if (
                    !response.isSuccessful || error != null || result.optString("status") == "error"
                )
                    throw Failure(error ?: "HTTP_ERROR", response.code)
                if (operation == "login") {
                    val role = result.optString("role")
                    if (role.isEmpty()) throw Failure("INVALID_RESPONSE")
                    val required =
                        if (result.optBoolean("staff", false)) "spdecode_staff_session"
                        else if (role == "owner") "spdecode_admin_session"
                        else throw Failure("INVALID_RESPONSE")
                    val valid =
                        response
                            .headers("Set-Cookie")
                            .mapNotNull { Cookie.parse(url, it) }
                            .filter {
                                it.name == required &&
                                    it.secure &&
                                    it.httpOnly &&
                                    it.hostOnly &&
                                    it.domain == base.host &&
                                    it.path == "/api/admin" &&
                                    it.expiresAt > now &&
                                    it.value.isNotEmpty()
                            }
                    session = valid.singleOrNull() ?: throw Failure("SESSION_COOKIE_MISSING")
                }
                return result
            }
        } catch (e: Failure) {
            throw e
        } catch (_: IOException) {
            throw Failure("NETWORK_ERROR")
        }
    }
}
