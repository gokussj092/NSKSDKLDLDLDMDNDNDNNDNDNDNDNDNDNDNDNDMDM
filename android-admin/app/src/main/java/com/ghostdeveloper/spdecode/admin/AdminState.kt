package com.ghostdeveloper.spdecode.admin

import android.app.Application
import androidx.compose.runtime.*
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import org.json.JSONArray
import org.json.JSONObject

internal fun JSONArray.objects(): List<JSONObject> =
    (0 until length()).mapNotNull { optJSONObject(it) }

internal fun JSONObject.array(key: String): List<JSONObject> =
    optJSONArray(key)?.objects().orEmpty()

internal class AdminState(app: Application) : AndroidViewModel(app) {
  private val api = AdminApi(SessionVault(app))
  private val preferences = app.getSharedPreferences("admin-display", 0)
  var appearance by
      mutableStateOf(
          runCatching { Appearance.valueOf(preferences.getString("appearance", "Amoled")!!) }
              .getOrDefault(Appearance.Amoled))
  var entered by mutableStateOf(false)
  var checking by mutableStateOf(true)
  var busy by mutableStateOf(false)
  var error by mutableStateOf<String?>(null)
  var message by mutableStateOf<String?>(null)
  var page by mutableStateOf(Page.Dashboard)
  var principal by mutableStateOf(JSONObject())
  var data by mutableStateOf(JSONObject())
  var detail by mutableStateOf<JSONObject?>(null)
  var selectedId by mutableStateOf("")
  var pageIndex by mutableIntStateOf(0)
  var search by mutableStateOf("")
  var oneTimeSecret by mutableStateOf<JSONObject?>(null)
  private var generation = 0
  private var taskRevision = 0
  val owner
    get() = principal.optString("role") == "owner"

  val mustChangePassword
    get() = principal.optBoolean("mustChangePassword")

  fun can(capability: String) =
      !mustChangePassword &&
          (principal.optJSONArray("capabilities")?.let { a ->
            (0 until a.length()).any { a.optString(it) == capability }
          } == true)

  init {
    viewModelScope.launch {
      try {
        principal = api.call("access").getJSONObject("principal")
        entered = true
        if (mustChangePassword) page = Page.Security else loadCurrent()
      } catch (e: Exception) {
        if ((e as? AdminApi.Failure)?.http == 401) api.clear()
        else error = errorText((e as? AdminApi.Failure)?.code ?: "NETWORK_ERROR")
      } finally {
        checking = false
      }
    }
  }

  fun theme(value: Appearance) {
    appearance = value
    preferences.edit().putString("appearance", value.name).apply()
  }

  fun allowed(p: Page): Boolean =
      when (p) {
        Page.Users,
        Page.UserDetail -> can("users.read")
        Page.Roles,
        Page.RoleDetail -> can("staff.read")
        Page.Support,
        Page.Chat -> can("support.read")
        Page.Finance,
        Page.Purchases,
        Page.Licenses,
        Page.Api,
        Page.Credits -> can("billing.read")
        Page.Logs -> can("audit.read")
        Page.Products,
        Page.Gifts,
        Page.Catalog,
        Page.Server,
        Page.Notices,
        Page.Broadcast,
        Page.Maintenance -> owner && !mustChangePassword
        else -> true
      }

  fun task(action: suspend () -> Unit) {
    if (busy) return
    taskRevision++
    busy = true
    error = null
    viewModelScope.launch {
      try {
        action()
      } catch (e: Exception) {
        val failure = e as? AdminApi.Failure
        if (failure?.http == 401) {
          api.clear()
          entered = false
          data = JSONObject()
          detail = null
          oneTimeSecret = null
        }
        error = errorText(failure?.code ?: "NETWORK_ERROR")
      } finally {
        busy = false
      }
    }
  }

  fun login(username: String, password: String) = task {
    api.clear()
    api.call(
        "login", input = JSONObject().put("username", username.trim()).put("password", password))
    principal = api.call("access").getJSONObject("principal")
    entered = true
    page = if (mustChangePassword) Page.Security else Page.Dashboard
    loadCurrent()
  }

  fun logout() = task { signOut() }

  suspend fun signOut() {
    try {
      api.call("logout", input = JSONObject())
    } finally {
      api.clear()
      entered = false
      principal = JSONObject()
      data = JSONObject()
      detail = null
      oneTimeSecret = null
      generation++
    }
  }

  fun navigate(p: Page, id: String = "") {
    if (busy || !allowed(p)) return
    page = p
    selectedId = id
    search = ""
    pageIndex = 0
    detail = null
    data = JSONObject()
    generation++
    refresh()
  }

  fun refresh() = task { loadCurrent() }

  // Foreground polling is deliberately separate from mutations and never disables the composer.
  suspend fun refreshSupport() {
    val current = page
    if (busy || !entered || current !in listOf(Page.Support, Page.Chat)) return
    val version = generation
    val revision = taskRevision
    try {
      val result = api.call("support")
      if (entered && !busy && generation == version && taskRevision == revision && page == current &&
          data.toString() != result.toString()) data = result
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      if ((e as? AdminApi.Failure)?.http == 401 && entered && !busy &&
          generation == version && taskRevision == revision) {
        api.clear()
        entered = false
        data = JSONObject()
        detail = null
        oneTimeSecret = null
        error = errorText("UNAUTHORIZED")
        generation++
      }
      // Transient polling failures leave the currently visible conversation intact.
    }
  }

  fun next(delta: Int) {
    if (busy) return
    pageIndex = (pageIndex + delta).coerceAtLeast(0)
    refresh()
  }

  suspend fun loadCurrent() {
    val current = page
    val version = generation
    val result =
        when (current) {
          Page.Dashboard ->
              if (owner) api.call("session") else JSONObject().put("principal", principal)
          Page.Users -> api.call("users", search.trim().removePrefix("@").take(80), pageIndex)
          Page.UserDetail -> api.call("user_detail", selectedId)
          Page.Roles -> api.call("staff")
          Page.Support,
          Page.Chat -> api.call("support")
          Page.Products -> api.call("store")
          Page.Gifts -> api.call("gifts")
          Page.Finance,
          Page.Purchases -> api.call("mobile", "orders", pageIndex)
          Page.Licenses -> api.call("mobile", "licenses", pageIndex)
          Page.Api -> api.call("mobile", "api", pageIndex)
          Page.Credits -> api.call("mobile", "credits", pageIndex)
          Page.Catalog -> api.call("session")
          Page.Server -> api.call("observability")
          Page.Notices -> api.call("notifications")
          Page.Logs -> api.call("audit")
          else -> JSONObject()
        }
    if (version == generation && current == page) data = result
  }

  suspend fun mutate(operation: String, input: JSONObject? = null) {
    val result = api.call(operation, input = input)
    if (result.has("temporaryPassword") || result.has("code")) oneTimeSecret = result
    if (operation == "password") {
      api.clear()
      entered = false
      data = JSONObject()
      message = "Contraseña actualizada. Inicia sesión con la nueva contraseña."
      return
    }
    message =
        if (result.optString("delivery").contains("failed"))
            "Aviso publicado. La entrega push falló; permanece disponible dentro de la aplicación."
        else if (result.optBoolean("queued")) "Solicitud registrada en el servidor."
        else "Guardado en el servidor."
    try {
      loadCurrent()
    } catch (e: Exception) {
      if ((e as? AdminApi.Failure)?.http == 401) throw e
      error = "La acción fue aceptada. No se pudo actualizar la pantalla; pulsa Actualizar."
    }
  }
}

internal fun errorText(code: String): String =
    when (code) {
      "INVALID_CREDENTIALS" -> "Usuario o contraseña incorrectos."
      "UNAUTHORIZED" -> "La sesión venció. Vuelve a iniciar sesión."
      "FORBIDDEN" -> "Tu cargo no tiene permiso para esta acción."
      "NETWORK_ERROR",
      "TIMEOUT" ->
          "No se pudo conectar con el servidor. Comprueba la conexión y vuelve a intentarlo."
      "RATE_LIMITED" -> "Demasiados intentos. Espera antes de volver a intentarlo."
      "SERVER_UPDATE_REQUIRED" -> "Esta sección necesita que se actualice el servidor."
      "SERVICE_UNAVAILABLE",
      "ADMIN_DISABLED" -> "El servicio administrativo no está disponible."
      "PRODUCT_CHANGED" ->
          "El producto cambió en el servidor. Actualiza la pantalla antes de editarlo."
      "INVALID_PUBLIC_IP" -> "Escribe una única dirección IP pública válida."
      "ENTITLEMENT_NOT_ACTIVE" -> "El pedido no está pagado o el acceso ya venció."
      "PASSWORD_CHANGE_REQUIRED" -> "Debes cambiar la contraseña temporal."
      else -> "No se pudo completar la operación ($code)."
    }
