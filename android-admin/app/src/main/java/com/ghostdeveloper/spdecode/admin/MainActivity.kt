package com.ghostdeveloper.spdecode.admin

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material.icons.automirrored.outlined.Send
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

internal val Mint = Color(0xFF34D9A4)
internal val Panel = Color(0xFF111516)
internal val GreenPanel = Color(0xFF10271F)
internal val Muted = Color(0xFFABABAB)
internal val Amber = Color(0xFFF4C76A)
internal val Red = Color(0xFFF87171)
internal val Blue = Color(0xFF60A5FA)
internal val Purple = Color(0xFFC4A0FF)
internal val Ink = Color(0xFFF7F7F7)
internal val Border = Color(0xFF232626)
internal val Rounded = RoundedCornerShape(16.dp)

private val Scheme = darkColorScheme(primary=Mint,onPrimary=Color(0xFF003322),background=Color.Black,onBackground=Ink,surface=Panel,onSurface=Ink,surfaceVariant=Panel,onSurfaceVariant=Muted,outline=Border,error=Red)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { MaterialTheme(colorScheme=Scheme) { AdminPreview() } }
    }
}

internal enum class Page(val title:String,val icon:ImageVector) {
    Dashboard("Resumen general",Icons.Outlined.Dashboard), Users("Usuarios",Icons.Outlined.People),
    Roles("Roles y permisos",Icons.Outlined.AdminPanelSettings), Support("Soporte",Icons.Outlined.Forum),
    Finance("Finanzas",Icons.Outlined.AccountBalanceWallet), Purchases("Transacciones",Icons.Outlined.ReceiptLong),
    Products("Productos",Icons.Outlined.ShoppingBag), Licenses("Licencias Offline",Icons.Outlined.VpnKey),
    Gifts("Gift codes",Icons.Outlined.CardGiftcard), Api("API comercial",Icons.Outlined.Code),
    Credits("Créditos",Icons.Outlined.Payments), Catalog("Catálogo VPN",Icons.Outlined.Storage),
    Server("Estado del servidor",Icons.Outlined.Dns), Notices("Notificaciones",Icons.Outlined.Notifications),
    Broadcast("Enviar notificación",Icons.Outlined.Campaign), Logs("Actividad del sistema",Icons.Outlined.History),
    Security("Centro de seguridad",Icons.Outlined.Security), Maintenance("Mantenimiento",Icons.Outlined.Build),
    Sessions("Mis sesiones",Icons.Outlined.Devices), Settings("Ajustes",Icons.Outlined.Settings),
    UserDetail("Detalles de usuario",Icons.Outlined.Person), Chat("Chat de soporte",Icons.Outlined.Forum)
}
private val primaryPages = listOf(Page.Dashboard,Page.Users,Page.Support,Page.Settings)
private val menuPages = Page.entries.filterNot { it==Page.UserDetail || it==Page.Chat }
internal data class DemoUser(val initials:String,val name:String,val email:String,val status:String,val tint:Color)
internal val demoUsers = listOf(
    DemoUser("AL","Alex_L","alex@example.com","Activo",Mint),
    DemoUser("NX","NexorX","nexor@example.com","Premium",Amber),
    DemoUser("MR","Marco_R","marco@example.com","Activo",Mint),
    DemoUser("DT","DarkTech","dark@example.com","Suspendido",Red)
)
internal data class DemoChat(val user:DemoUser,val message:String,val time:String,val unread:Int)
internal val demoChats = listOf(DemoChat(demoUsers[1],"Tengo un problema con mi licencia.","09:38",2),DemoChat(demoUsers[0],"Muchas gracias por la ayuda.","09:21",0),DemoChat(demoUsers[2],"No puedo iniciar sesión.","08:56",1),DemoChat(demoUsers[3],"¿Cuándo estará disponible?","08:40",3))

@OptIn(ExperimentalMaterial3Api::class)
@Composable private fun AdminPreview() {
    var entered by rememberSaveable { mutableStateOf(false) }
    var page by rememberSaveable { mutableStateOf(Page.Dashboard.name) }
    var selectedUser by rememberSaveable { mutableIntStateOf(1) }
    var selectedChat by rememberSaveable { mutableIntStateOf(0) }
    val current = Page.valueOf(page)
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    fun go(p:Page){ page=p.name }
    fun back(){ go(when(current){ Page.UserDetail->Page.Users; Page.Chat->Page.Support; Page.Broadcast->Page.Notices; Page.Sessions->Page.Security; else->Page.Dashboard }) }
    BackHandler(entered && current!=Page.Dashboard){back()}
    if(!entered){ Login { entered=true }; return }
    ModalNavigationDrawer(drawerState=drawer,drawerContent={
        ModalDrawerSheet(drawerContainerColor=Color.Black,modifier=Modifier.width(304.dp)) {
            LazyColumn(contentPadding=PaddingValues(16.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
                item { Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)){ Avatar(Icons.Outlined.VerifiedUser,Mint,48); Column { Text("Administrador",fontWeight=FontWeight.SemiBold); Small("SP-DECODE · Vista previa") } }; Spacer(Modifier.height(12.dp)); HorizontalDivider(color=Border) }
                items(menuPages.size){ i-> val p=menuPages[i]; NavigationDrawerItem(label={Text(if(p==Page.Dashboard)"Dashboard" else p.title)},selected=current==p,icon={Icon(p.icon,null)},onClick={go(p);scope.launch{drawer.close()}},colors=NavigationDrawerItemDefaults.colors(selectedContainerColor=GreenPanel,selectedIconColor=Mint,selectedTextColor=Mint,unselectedContainerColor=Color.Black,unselectedIconColor=Muted,unselectedTextColor=Ink)) }
                item { TextButton(onClick={entered=false;go(Page.Dashboard);scope.launch{drawer.close()}}){Icon(Icons.Outlined.Logout,null,tint=Red);Spacer(Modifier.width(10.dp));Text("Salir de la vista previa",color=Red)} }
            }
        }
    }){
        Scaffold(containerColor=Color.Black,topBar={
            TopAppBar(title={Text(if(current==Page.Dashboard)"SP-DECODE Admin" else if(current==Page.Chat) demoChats[selectedChat].user.name else current.title,fontSize=19.sp,fontWeight=FontWeight.Medium)},navigationIcon={
                IconButton(onClick={if(current in listOf(Page.Chat,Page.UserDetail,Page.Broadcast,Page.Sessions))back() else scope.launch{drawer.open()}}){Icon(if(current in listOf(Page.Chat,Page.UserDetail,Page.Broadcast,Page.Sessions))Icons.AutoMirrored.Outlined.ArrowBack else Icons.Outlined.Menu,"Navegación")}
            },actions={IconButton(onClick={go(Page.Notices)}){Icon(Icons.Outlined.Notifications,"Notificaciones",tint=Mint)}},colors=TopAppBarDefaults.topAppBarColors(containerColor=Color.Black))
        },bottomBar={if(current in primaryPages) NavigationBar(containerColor=Color.Black){primaryPages.forEach{ p-> NavigationBarItem(selected=current==p,onClick={go(p)},icon={Icon(p.icon,p.title)},label={Text(when(p){Page.Dashboard->"Inicio";else->p.title})},colors=NavigationBarItemDefaults.colors(selectedIconColor=Mint,selectedTextColor=Mint,indicatorColor=GreenPanel,unselectedIconColor=Muted,unselectedTextColor=Muted))}}}){ padding ->
            Column(Modifier.fillMaxSize().padding(padding)){
                Text("VISTA PREVIA · DATOS FICTICIOS · SIN CONEXIÓN",color=Amber,fontSize=10.sp,modifier=Modifier.fillMaxWidth().background(Color(0xFF201B12)).padding(6.dp),textAlign=TextAlign.Center)
                when(current){
                    Page.Dashboard->Dashboard()
                    Page.Users->Users{selectedUser=it;go(Page.UserDetail)}
                    Page.UserDetail->UserDetail(demoUsers[selectedUser]){go(it)}
                    Page.Roles->Roles()
                    Page.Support->Support{selectedChat=it;go(Page.Chat)}
                    Page.Chat->Chat(demoChats[selectedChat])
                    else->ModuleScreen(current){go(it)}
                }
            }
        }
    }
}

@Composable private fun Login(enter:()->Unit){
    // No credentials are accepted, stored or transmitted in this isolated preview.
    Column(Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding().padding(24.dp),verticalArrangement=Arrangement.Center,horizontalAlignment=Alignment.CenterHorizontally){
        Avatar(Icons.Outlined.VerifiedUser,Mint,76);Spacer(Modifier.height(20.dp))
        Text("SP-DECODE",fontSize=30.sp,fontWeight=FontWeight.Bold)
        Text("ADMINISTRATION",color=Mint,fontSize=15.sp,fontWeight=FontWeight.Medium)
        Small("Acceso restringido · prototipo");Spacer(Modifier.height(28.dp))
        OutlinedTextField(value="Administrador",onValueChange={},readOnly=true,label={Text("Usuario")},leadingIcon={Icon(Icons.Outlined.Person,null)},shape=Rounded,modifier=Modifier.fillMaxWidth())
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(value="demostracion",onValueChange={},readOnly=true,visualTransformation=PasswordVisualTransformation(),label={Text("Contraseña")},leadingIcon={Icon(Icons.Outlined.Lock,null)},shape=Rounded,modifier=Modifier.fillMaxWidth())
        Spacer(Modifier.height(20.dp));Button(onClick=enter,shape=Rounded,modifier=Modifier.fillMaxWidth().height(52.dp)){Text("Abrir vista previa",fontWeight=FontWeight.SemiBold)}
        Spacer(Modifier.height(24.dp));Icon(Icons.Outlined.Fingerprint,null,Modifier.size(40.dp),tint=Mint);Small("Biometría pendiente de integración")
        Spacer(Modifier.height(24.dp));Small("Ghost Nexora Studio")
    }
}
@Composable internal fun Small(value:String,modifier:Modifier=Modifier,color:Color=Muted){Text(value,modifier=modifier,color=color,fontSize=12.sp,maxLines=2,overflow=TextOverflow.Ellipsis)}
@Composable internal fun Avatar(icon:ImageVector,tint:Color=Mint,size:Int=42){Box(Modifier.size(size.dp).background(tint.copy(alpha=.12f),RoundedCornerShape(14.dp)),contentAlignment=Alignment.Center){Icon(icon,null,tint=tint,modifier=Modifier.size((size*.52).dp))}}
@Composable internal fun Initials(user:DemoUser){Box(Modifier.size(42.dp).background(user.tint.copy(alpha=.19f),CircleShape),contentAlignment=Alignment.Center){Text(user.initials,color=user.tint,fontWeight=FontWeight.Medium)}}
@Composable internal fun Tile(modifier:Modifier=Modifier,color:Color=Panel,content:@Composable ColumnScope.()->Unit){Column(modifier.background(color,Rounded).padding(14.dp),verticalArrangement=Arrangement.spacedBy(7.dp),content=content)}
@Composable internal fun StaticAction(label:String){FilledTonalButton(onClick={},enabled=false,shape=Rounded,modifier=Modifier.fillMaxWidth(),colors=ButtonDefaults.filledTonalButtonColors(disabledContainerColor=GreenPanel,disabledContentColor=Mint.copy(alpha=.7f))){Text(label)}}
@Composable internal fun ScreenList(content:androidx.compose.foundation.lazy.LazyListScope.()->Unit){LazyColumn(Modifier.fillMaxSize(),contentPadding=PaddingValues(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp),content=content)}
@Composable internal fun Metric(label:String,value:String,icon:ImageVector,tint:Color=Mint,modifier:Modifier=Modifier){Tile(modifier){Icon(icon,null,tint=tint);Text(value,fontSize=25.sp,fontWeight=FontWeight.SemiBold,color=Ink);Small(label)}}
@Composable internal fun Trend(){Canvas(Modifier.fillMaxWidth().height(90.dp)){repeat(4){ val y=size.height*it/3;drawLine(Border,Offset(0f,y),Offset(size.width,y),strokeWidth=1f)}; val points=listOf(.84f,.68f,.74f,.44f,.57f,.32f,.45f,.16f,.26f,.06f);val p=Path();points.forEachIndexed{i,y->val x=size.width*i/(points.size-1);if(i==0)p.moveTo(x,size.height*y) else p.lineTo(x,size.height*y)};drawPath(p,Mint,style=androidx.compose.ui.graphics.drawscope.Stroke(width=3.dp.toPx()))}}
@Composable private fun Dashboard(){ScreenList{
    item{Small("Panel administrativo");Text("Resumen general",fontSize=27.sp,fontWeight=FontWeight.Bold);Text("●  Servidor operativo",color=Mint,fontSize=13.sp)}
    item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Usuarios","1,284",Icons.Outlined.People,modifier=Modifier.weight(1f));Metric("Ingresos","$248.50",Icons.Outlined.AccountBalanceWallet,modifier=Modifier.weight(1f))}}
    item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Tickets","12",Icons.Outlined.Forum,modifier=Modifier.weight(1f));Metric("Licencias","86",Icons.Outlined.VpnKey,modifier=Modifier.weight(1f))}}
    item{Tile{Text("Actividad del servicio",fontWeight=FontWeight.Medium);Trend()}}
}}
@Composable private fun Users(open:(Int)->Unit){var query by rememberSaveable{mutableStateOf("")};var filter by rememberSaveable{mutableStateOf("Todos")};ScreenList{
    item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Registrados","1,284",Icons.Outlined.People,modifier=Modifier.weight(1f));Metric("Activos hoy","326",Icons.Outlined.Person,modifier=Modifier.weight(1f))}}
    item{OutlinedTextField(query,{query=it},placeholder={Text("Buscar usuario...")},leadingIcon={Icon(Icons.Outlined.Search,null)},singleLine=true,shape=CircleShape,modifier=Modifier.fillMaxWidth())}
    item{Row(horizontalArrangement=Arrangement.spacedBy(6.dp)){listOf("Todos","Activos","Suspendidos").forEach{f->FilterChip(filter==f,{filter=f},{Text(f,fontSize=11.sp)})}}}
    items(demoUsers.size){i->val u=demoUsers[i];if((filter=="Todos" || (filter=="Activos"&&u.status!="Suspendido") || (filter=="Suspendidos"&&u.status=="Suspendido")) && (u.name.contains(query,true)||u.email.contains(query,true))){Row(Modifier.fillMaxWidth().clickable{open(i)}.padding(vertical=6.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)){Initials(u);Column(Modifier.weight(1f)){Text(u.name,fontWeight=FontWeight.Medium);Small(u.email);Small(u.status,color=u.tint)};Icon(Icons.Outlined.ChevronRight,null,tint=Muted)};HorizontalDivider(color=Border)}}
}}
@Composable private fun UserDetail(user:DemoUser,go:(Page)->Unit){ScreenList{
    item{Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally,verticalArrangement=Arrangement.spacedBy(6.dp)){Initials(user);Text(user.name,fontSize=24.sp,fontWeight=FontWeight.Bold);Small(user.email);Small("● "+user.status,color=user.tint)}}
    item{Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){Metric("Compras","4",Icons.Outlined.ShoppingBag,modifier=Modifier.weight(1f));Metric("Créditos","25",Icons.Outlined.Payments,modifier=Modifier.weight(1f))}}
    items(5){i->val (name,p)=listOf("Editar perfil" to Page.Settings,"Historial de compras" to Page.Purchases,"Dispositivos y sesiones" to Page.Sessions,"Licencias y productos" to Page.Licenses,"Historial de actividad" to Page.Logs)[i]; Row(Modifier.fillMaxWidth().clickable{go(p)}.padding(vertical=8.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(12.dp)){Icon(p.icon,null,tint=Mint);Text(name,Modifier.weight(1f));Icon(Icons.Outlined.ChevronRight,null,tint=Muted)};HorizontalDivider(color=Border)}
    item{StaticAction("Suspender cuenta · no disponible")}
}}
@Composable private fun Roles(){ScreenList{
    items(4){i->val data=listOf(Triple("Propietario","Acceso global · 1 miembro",Amber),Triple("Administrador","Gestión administrativa · 2 miembros",Mint),Triple("Soporte técnico","Tickets y asistencia · 3 miembros",Blue),Triple("Finanzas","Compras y pagos · 1 miembro",Purple))[i];Tile{Row(horizontalArrangement=Arrangement.spacedBy(12.dp),verticalAlignment=Alignment.CenterVertically){Avatar(Icons.Outlined.AdminPanelSettings,data.third);Column{Text(data.first,fontWeight=FontWeight.Medium);Small(data.second)}}}}
    item{StaticAction("+ Crear nuevo cargo")}
}}
@Composable private fun Support(open:(Int)->Unit){var filter by rememberSaveable{mutableStateOf("Todos")};ScreenList{
    item{Row(horizontalArrangement=Arrangement.spacedBy(6.dp)){listOf("Todos","Pendientes","Cerrados").forEach{FilterChip(filter==it,{filter=it},{Text(it,fontSize=11.sp)})}}}
    items(demoChats.size){i->val c=demoChats[i];if(filter=="Todos"||(filter=="Pendientes"&&c.unread>0)||(filter=="Cerrados"&&c.unread==0)){Row(Modifier.fillMaxWidth().clickable{open(i)}.padding(vertical=8.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)){Initials(c.user);Column(Modifier.weight(1f)){Text(c.user.name,fontWeight=FontWeight.Medium);Small(c.message)};Column(horizontalAlignment=Alignment.End){Small(c.time);if(c.unread>0)Box(Modifier.size(22.dp).background(Mint,CircleShape),contentAlignment=Alignment.Center){Text(c.unread.toString(),color=Color.Black,fontSize=12.sp)}}};HorizontalDivider(color=Border)}}
}}
@Composable private fun Chat(chat:DemoChat){Column(Modifier.fillMaxSize().padding(16.dp),verticalArrangement=Arrangement.spacedBy(14.dp)){
    Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween){Small("Ticket #00284");Small("● Abierto",color=Mint)}
    Small("Hoy",Modifier.fillMaxWidth(),color=Muted)
    Tile(Modifier.fillMaxWidth(.86f)){Text(chat.message);Small("09:34")}
    Tile(Modifier.align(Alignment.End).fillMaxWidth(.86f),GreenPanel){Small("Administrador",color=Mint);Text("Hola. ¿Podrías enviarme el número de tu pedido?");Small("09:35  ✓✓")}
    Tile(Modifier.fillMaxWidth(.86f)){Text("Sí, es el pedido SPD-2048.");Small("09:38")}
    Spacer(Modifier.weight(1f));Small("Asignado a: Administrador")
    Row(verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(8.dp)){Icon(Icons.Outlined.AttachFile,null,tint=Muted);Box(Modifier.weight(1f).background(Panel,CircleShape).padding(14.dp)){Small("Escribir mensaje...")};Box(Modifier.size(38.dp).background(Mint,CircleShape),contentAlignment=Alignment.Center){Icon(Icons.AutoMirrored.Outlined.Send,null,Modifier.size(19.dp),tint=Color.Black)}}
}}
