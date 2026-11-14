package com.ghostdeveloper.spdecode.admin

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private data class Entry(val title:String,val subtitle:String,val detail:String="",val tint:Color=Mint)
@Composable private fun EntryCard(entry:Entry,icon:ImageVector?=null){Tile(Modifier.fillMaxWidth()){
    Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)){
        if(icon!=null)Avatar(icon,entry.tint,40)
        Column(Modifier.weight(1f)){Text(entry.title,fontWeight=FontWeight.Medium);Small(entry.subtitle)}
        if(entry.detail.isNotEmpty())Text(entry.detail,color=entry.tint,fontSize=12.sp)
    }
}}
@Composable private fun LinkRow(title:String,icon:ImageVector,go:()->Unit){Row(Modifier.fillMaxWidth().clickable(onClick=go).padding(vertical=10.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)){Icon(icon,null,tint=Mint);Text(title,Modifier.weight(1f));Icon(Icons.Outlined.ChevronRight,null,tint=Muted)}}
@Composable private fun Meter(label:String,value:Int,color:Color){Tile(Modifier.fillMaxWidth()){
    Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween){Text(label);Text("$value%",color=color)}
    LinearProgressIndicator(progress={value/100f},modifier=Modifier.fillMaxWidth().height(7.dp),color=color,trackColor=Border)
}}
@Composable private fun Hero(label:String,value:String,subtitle:String,chart:Boolean=false){Tile(Modifier.fillMaxWidth(),GreenPanel){Small(label);Text(value,fontSize=32.sp,fontWeight=FontWeight.Bold,color=Mint);Small(subtitle,color=Mint);if(chart)Trend()}}
@Composable private fun SearchBox(query:String,change:(String)->Unit,placeholder:String){OutlinedTextField(query,change,placeholder={Text(placeholder)},leadingIcon={Icon(Icons.Outlined.Search,null)},singleLine=true,shape=CircleShape,modifier=Modifier.fillMaxWidth())}
@Composable private fun Field(label:String,value:String){Column(verticalArrangement=Arrangement.spacedBy(4.dp)){Small(label);Tile(Modifier.fillMaxWidth()){Text(value)}}}
@Composable private fun Records(data:List<Entry>,search:String?=null,action:String?=null,icon:ImageVector?=null){var query by rememberSaveable{mutableStateOf("")};val filtered=data.filter{it.title.contains(query,true)||it.subtitle.contains(query,true)||it.detail.contains(query,true)};ScreenList{
    if(search!=null)item{SearchBox(query,{query=it},search)}
    items(filtered.size){EntryCard(filtered[it],icon)}
    if(action!=null)item{StaticAction(action)}
}}
@Composable internal fun ModuleScreen(page:Page,go:(Page)->Unit){
    when(page){
        Page.Finance->ScreenList{
            item{Hero("Ingresos totales","$1,248.50","+18.4% este mes",true)}
            item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Ventas","248",Icons.Outlined.ReceiptLong,modifier=Modifier.weight(1f));Metric("Por confirmar","3",Icons.Outlined.Schedule,Amber,Modifier.weight(1f))}}
            item{Text("Métodos de pago",fontWeight=FontWeight.Medium)}
            item{Meter("PayPal · $628.50",50,Blue)}
            item{Meter("Stripe · $420.00",34,Purple)}
            item{Meter("Mercado Pago · $200.00",16,Mint)}
            item{LinkRow("Historial de operaciones",Icons.Outlined.ReceiptLong){go(Page.Purchases)}}
        }
        Page.Purchases->Records(listOf(Entry("Licencia Offline","#SPD-2048 · NexorX · PayPal","+$4.99"),Entry("API comercial","#SPD-2047 · Alex_L · Stripe","+$19.99"),Entry("Créditos APK","#SPD-2046 · Mercado Pago","$3.99",Amber),Entry("Licencia Offline","#SPD-2045 · Reembolso","$4.99",Red)),"Buscar pedido...")
        Page.Products->ScreenList{
            items(3){i->val e=listOf(Entry("SP-DECODE Offline","Licencia · 3 dispositivos","$4.99"),Entry("API comercial","Acceso por IP autorizada","$19.99",Blue),Entry("Análisis APK","Paquete de créditos","$3.99",Amber))[i];Tile{Row(horizontalArrangement=Arrangement.spacedBy(12.dp),verticalAlignment=Alignment.CenterVertically){Avatar(listOf(Icons.Outlined.Memory,Icons.Outlined.Code,Icons.Outlined.Inventory2)[i],e.tint,48);Column{Text(e.title,fontWeight=FontWeight.Medium);Small(e.subtitle)}};Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween){Text(e.detail,fontSize=22.sp,fontWeight=FontWeight.SemiBold);Small("● Disponible",color=Mint)};StaticAction("Editar producto")}}
        }
        Page.Licenses->ScreenList{
            item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Activas","86",Icons.Outlined.VpnKey,modifier=Modifier.weight(1f));Metric("Revocadas","4",Icons.Outlined.Block,Red,Modifier.weight(1f))}}
            items(3){i->val e=listOf(Entry("NexorX","SPD-••••-••••-A81C · 2 de 3 dispositivos","Activa"),Entry("Alex_L","SPD-••••-••••-B92D · 1 de 3 dispositivos","Activa"),Entry("Marco_R","SPD-••••-••••-F34B · 3 de 3 dispositivos","Activa"))[i];EntryCard(e,Icons.Outlined.VpnKey)}
            item{StaticAction("+ Generar licencia")}
        }
        Page.Gifts->ScreenList{
            item{Tile(Modifier.fillMaxWidth(),GreenPanel){Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally){Icon(Icons.Outlined.CardGiftcard,null,Modifier.size(42.dp),tint=Mint);Text("Crear código",fontSize=22.sp,fontWeight=FontWeight.Medium);Small("Genera recompensas para tus usuarios.")}}}
            item{Field("Recompensa","Licencia Offline")}
            item{Field("Cantidad de usos","1 usuario")}
            item{Field("Caducidad","Sin vencimiento")}
            item{Field("Dispositivos","3 dispositivos")}
            item{StaticAction("Generar gift code")}
        }
        Page.Api->ScreenList{
            item{Hero("Solicitudes realizadas hoy","12,842","8 clientes con acceso activo")}
            items(3){i->EntryCard(listOf(Entry("Cliente #001","IP: 192.0.2.10 · 8,240 solicitudes","Activa"),Entry("Cliente #002","IP: 198.51.100.24 · 4,602 solicitudes","Activa"),Entry("Cliente #003","IP: 203.0.113.12 · 0 solicitudes","Revocada",Red))[i],Icons.Outlined.Code)}
            item{StaticAction("Crear acceso API")}
        }
        Page.Credits->Records(listOf(Entry("NexorX","Saldo de créditos","25"),Entry("Alex_L","Saldo de créditos","10"),Entry("Marco_R","Saldo de créditos","0",Amber)),"Buscar usuario...","Asignar créditos",Icons.Outlined.Payments)
        Page.Catalog->CatalogPreview()
        Page.Server->ScreenList{
            item{Hero("● Operativo","14d 08h 32m","Tiempo en línea")}
            item{Meter("Procesador",24,Mint)}
            item{Meter("Memoria RAM",38,Blue)}
            item{Meter("Almacenamiento",18,Purple)}
            item{Text("Servicios",fontWeight=FontWeight.Medium)}
            items(5){i->Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)){Icon(Icons.Outlined.CheckCircle,null,tint=Mint,modifier=Modifier.size(18.dp));Text(listOf("Nginx","Web API","Worker","PostgreSQL","Redis")[i],Modifier.weight(1f));Small("Online",color=Mint)}}
        }
        Page.Notices->ScreenList{
            item{LinkRow("Enviar notificación",Icons.Outlined.Campaign){go(Page.Broadcast)}}
            item{Small("HOY")}
            items(5){i->val e=listOf(Entry("Nueva compra","Licencia Offline · $4.99","2 min"),Entry("Mensaje de soporte","NexorX envió un mensaje.","4 min",Blue),Entry("Nuevo usuario","Una cuenta se ha registrado.","15 min",Purple),Entry("Alerta de servicio","Uso elevado de memoria.","38 min",Amber),Entry("Catálogo actualizado","Nueva versión publicada.","1 h"))[i];EntryCard(e,listOf(Icons.Outlined.ShoppingBag,Icons.Outlined.Forum,Icons.Outlined.PersonAdd,Icons.Outlined.Warning,Icons.Outlined.Storage)[i])}
        }
        Page.Broadcast->ScreenList{
            item{Field("Destinatarios","Todos los usuarios")}
            item{Field("Tipo de aviso","Actualización de catálogo")}
            item{Field("Título","Nueva actualización disponible")}
            item{Field("Mensaje","Ya puedes descargar la nueva versión del catálogo de SP-DECODE.")}
            item{Row(verticalAlignment=Alignment.CenterVertically){Text("Mostrar aviso dentro de la app",Modifier.weight(1f));Switch(checked=true,onCheckedChange=null,enabled=false)}}
            item{Tile(color=GreenPanel){Small("14 idiomas · Multiidioma",color=Mint)}}
            item{StaticAction("Enviar notificación")}
        }
        Page.Logs->ScreenList{
            item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Operaciones","8,420",Icons.Outlined.History,modifier=Modifier.weight(1f));Metric("Tasa de éxito","99.2%",Icons.Outlined.CheckCircle,modifier=Modifier.weight(1f))}}
            items(5){i->EntryCard(listOf(Entry("INFO","Solicitud procesada","09:41:28"),Entry("INFO","Catálogo sincronizado","09:40:12"),Entry("WARN","Tiempo de espera excedido","09:38:25",Amber),Entry("ERROR","Servicio no disponible","09:35:46",Red),Entry("INFO","Servicio recuperado","09:32:18"))[i])}
            item{StaticAction("Exportar registros")}
        }
        Page.Security->ScreenList{
            item{Tile(Modifier.fillMaxWidth(),GreenPanel){Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally){Icon(Icons.Outlined.VerifiedUser,null,Modifier.size(46.dp),tint=Mint);Text("Protección · vista previa",color=Mint,fontSize=21.sp);Small("Autenticación real pendiente")}}}
            items(4){i->EntryCard(listOf(Entry("Acceso biométrico","Pendiente de integración",""),Entry("Autenticación 2FA","Pendiente de integración",""),Entry("Cambiar contraseña","No disponible en preview",""),Entry("Control de accesos","No disponible en preview",""))[i],Icons.Outlined.Security)}
            item{LinkRow("Dispositivos y sesiones",Icons.Outlined.Devices){go(Page.Sessions)}}
            item{LinkRow("Auditoría administrativa",Icons.Outlined.History){go(Page.Logs)}}
        }
        Page.Maintenance->ScreenList{
            items(4){i->val e=listOf(Entry("Caché del sistema","148 MB utilizados","Limpiar caché"),Entry("Copias de seguridad","Cuentas, pagos y licencias","Crear respaldo",Blue),Entry("Servicios","5 servicios operativos","Gestionar servicios"),Entry("Modo mantenimiento","Actualmente desactivado","Configurar mantenimiento",Amber))[i];Tile{Row(horizontalArrangement=Arrangement.spacedBy(10.dp),verticalAlignment=Alignment.CenterVertically){Avatar(listOf(Icons.Outlined.Storage,Icons.Outlined.Backup,Icons.Outlined.Refresh,Icons.Outlined.Build)[i],e.tint);Column{Text(e.title);Small(e.subtitle)}};StaticAction(e.detail)}}
        }
        Page.Sessions->Records(listOf(Entry("Android 16","SP-DECODE Admin · vista previa","Este dispositivo"),Entry("Windows · Chrome","Panel administrativo web · hace 2 horas"),Entry("Android 15","SP-DECODE Admin · ayer")),action="Cerrar las demás sesiones",icon=Icons.Outlined.Devices)
        Page.Settings->SettingsPreview(go)
        else->ScreenList{item{Small("Vista previa")}}
    }
}
@Composable private fun CatalogPreview(){var q by rememberSaveable{mutableStateOf("")};val rows=listOf(Entry("HTTP Custom","Método activo",""),Entry("HTTP Injector","Método activo",""),Entry("HA Tunnel Plus","Catálogo activo",""),Entry("Litron VPN","Catálogo desactivado","",Amber)).filter{it.title.contains(q,true)};ScreenList{
    item{Hero("Versión del catálogo","215686799","108 aplicaciones registradas")}
    item{SearchBox(q,{q=it},"Buscar aplicación...")}
    items(rows.size){i->val e=rows[i];Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)){Avatar(Icons.Outlined.Shield,e.tint);Column(Modifier.weight(1f)){Text(e.title);Small(e.subtitle,color=e.tint)};Switch(checked=e.tint==Mint,onCheckedChange=null,enabled=false)};HorizontalDivider(color=Border)}
    item{StaticAction("Publicar actualización")}
}}
@Composable private fun SettingsPreview(go:(Page)->Unit){ScreenList{
    item{Row(horizontalArrangement=Arrangement.spacedBy(12.dp),verticalAlignment=Alignment.CenterVertically){Avatar(Icons.Outlined.VerifiedUser,Mint,55);Column{Text("Administrador",fontWeight=FontWeight.Medium);Small("Propietario · datos ficticios",color=Mint)}}}
    item{Small("APARIENCIA",color=Mint);Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){listOf("AMOLED" to Color.Black,"Oscuro" to Color(0xFF24272B),"Claro" to Color(0xFFF5F5F5)).forEach{(name,c)->Column(Modifier.weight(1f),horizontalAlignment=Alignment.CenterHorizontally,verticalArrangement=Arrangement.spacedBy(5.dp)){Box(Modifier.fillMaxWidth().height(74.dp).background(if(name=="AMOLED")Mint else Border,RoundedCornerShape(12.dp)).padding(2.dp)){Column(Modifier.fillMaxSize().background(c,RoundedCornerShape(10.dp)).padding(8.dp),verticalArrangement=Arrangement.spacedBy(6.dp)){Box(Modifier.fillMaxWidth(.65f).height(5.dp).background(Mint,CircleShape));repeat(2){Box(Modifier.fillMaxWidth().height(16.dp).background(if(name=="Claro")Color(0xFFD9E2E1)else Panel,RoundedCornerShape(4.dp)))}}};Small(name,color=if(name=="AMOLED")Mint else Muted)}}}}
    item{EntryCard(Entry("Idioma","Español · preview",""),Icons.Outlined.Language)}
    item{LinkRow("Notificaciones",Icons.Outlined.Notifications){go(Page.Notices)}}
    item{LinkRow("Privacidad y seguridad",Icons.Outlined.Security){go(Page.Security)}}
    item{EntryCard(Entry("Buscar actualización","No disponible en preview"),Icons.Outlined.Download)}
    item{EntryCard(Entry("Acerca de","SP-DECODE Admin · 1.0.0-dev"),Icons.Outlined.Info)}
}}
