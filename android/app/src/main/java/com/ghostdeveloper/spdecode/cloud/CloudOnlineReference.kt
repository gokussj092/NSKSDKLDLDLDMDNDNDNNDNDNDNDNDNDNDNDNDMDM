package com.ghostdeveloper.spdecode.cloud

import com.ghostdeveloper.spdecode.HttpInjectorCloudPort
import java.net.URI
import java.util.Locale

/** Only UI discovery. The VPS owns the vendor allowlists, worker routes and secrets. */
internal object CloudOnlineReference {
    data class Provider(val id:String,val name:String)
    data class Resolved(val provider:String,val reference:String,
        val name:String,val suffix:String,val filename:String)

    fun options(routes:List<CloudTextRoute>):List<Provider> {
        val builtIn=listOf(Provider("ehi","HTTP Injector Cloud"),
            Provider("hc","HTTP Custom Cloud"),
            Provider("hexcustom","Hex Custom Cloud"),
            Provider("tunneltweak","Tunneltweak Cloud"),
            Provider("mnr","MNR Tunnel Plus"))
        val declared=routes.asSequence().filter {
            it.kind=="cloud" && it.prefix.startsWith("https://",ignoreCase=true) &&
                it.suffix !in setOf("ehi","hc") &&
                it.suffix.matches(Regex("[a-z0-9_-]{1,32}"))
        }.distinctBy{it.suffix}.take(32).map{Provider(it.suffix,it.name)}.toList()
        return builtIn+declared
    }

    private fun httpCustom(value:String):String? {
        if(HttpCustomCloudReference.matches(value))return value
        val alias=Regex("^hccloud://(playsmarty|mrfrank)/([A-Za-z0-9_-]{1,64})$",
            RegexOption.IGNORE_CASE).matchEntire(value)?:return null
        val name=alias.groupValues[1].lowercase(Locale.ROOT)
        val url=when(name) {
            "playsmarty" -> "https://link.playsmarty.uk/"+alias.groupValues[2]
            "mrfrank" -> "https://cloudvpn.mrfrankofc.com/"+alias.groupValues[2]
            else -> return null
        }
        return url.takeIf(HttpCustomCloudReference::matches)
    }

    private fun injector(value:String):String? =
        try {HttpInjectorCloudPort.parseReference(value)}
        catch(_:HttpInjectorCloudPort.CloudException){null}

    /** Bare Hex Custom cloud key, never a URL. Same shape the server validates
     * in c35-provider (parseHexCustomReference): "HexCustom-" + 10 alphanumerics.
     * The hyphen keeps it out of the injector key alphabet, so it can never
     * be mistaken for an ehi key; checked before injector anyway. */
    private fun hexCustomReference(value:String):String? =
        value.takeIf { Regex("^HexCustom-[A-Za-z0-9]{10}$").matches(it) }

    /** MNR cloud reference. Same shape the server validates in c35-provider
     * (parseMnrReference); the scheme is lowercase, exactly as the server. */
    private fun mnrReference(value:String):String? =
        value.takeIf { Regex("^mnrtunneludp://[A-Za-z0-9]{10}$").matches(it) }

    /** UUIDs are not provider-identifying. Tunneltweak is the only explicitly
     * configured Cloud UUID broker today; never form arbitrary URLs here.
     * A namespaced reference remains unambiguous if other UUID apps are added. */
    private fun tunneltweakReference(value:String):String? {
        val bare=if(value.startsWith("tunneltweak://",ignoreCase=true))
            value.substring("tunneltweak://".length) else value
        val pattern=Regex("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
        return bare.takeIf(pattern::matches)?.lowercase(Locale.ROOT)
    }

    private fun declaredRemote(value:String,routes:List<CloudTextRoute>):CloudTextRoute? {
        val input=try{URI(value)}catch(_:Exception){return null}
        if(input.scheme!="https" || input.host.isNullOrBlank() ||
            input.port!=-1 || input.rawUserInfo!=null ||
            input.rawQuery!=null || input.rawFragment!=null)return null
        return routes.asSequence().filter{
            it.kind=="cloud" && it.suffix !in setOf("hc","ehi") &&
            it.prefix.startsWith("https://",ignoreCase=true) &&
            it.suffix.matches(Regex("[a-z0-9_-]{1,32}")) &&
            value.startsWith(it.prefix,ignoreCase=true) &&
            value.length>it.prefix.length
        }.filter{declared->
            val base=try{URI(declared.prefix)}catch(_:Exception){null}
            base!=null && base.host.equals(input.host,ignoreCase=true) &&
            input.rawPath.orEmpty().startsWith(base.rawPath.orEmpty()) &&
            input.rawPath.orEmpty().matches(Regex("/[A-Za-z0-9/_-]{1,256}"))
        }.maxByOrNull{it.prefix.length}
    }

    fun resolve(reference:String,choice:String,routes:List<CloudTextRoute>):Resolved? {
        val value=reference.trim().removePrefix("\uFEFF")
        if(value.isBlank() || value.length>1024)return null
        val hc=httpCustom(value)
        val hex=if(hc==null)hexCustomReference(value) else null
        val mnr=if(hc==null&&hex==null)mnrReference(value) else null
        val tweak=if(hc==null&&hex==null&&mnr==null)tunneltweakReference(value) else null
        val ehi=if(hc==null&&hex==null&&mnr==null&&tweak==null)injector(value) else null
        val remote=if(hc==null&&hex==null&&mnr==null&&tweak==null&&ehi==null)declaredRemote(value,routes) else null
        val selected=when(choice){
            "auto" -> when {hc!=null->"hc";hex!=null->"hexcustom";mnr!=null->"mnr";tweak!=null->"tunneltweak";ehi!=null->"ehi";remote!=null->remote.suffix;else->return null}
            "hc" -> if(hc!=null)"hc" else return null
            "hexcustom" -> if(hex!=null)"hexcustom" else return null
            "mnr" -> if(mnr!=null)"mnr" else return null
            "tunneltweak" -> if(tweak!=null)"tunneltweak" else return null
            "ehi" -> if(injector(value)!=null)"ehi" else return null
            else -> if(remote?.suffix==choice && options(routes).any{it.id==choice})choice else return null
        }
        return when(selected){
            "hc" -> Resolved("hc",hc!!,"HTTP Custom Cloud","hc","http-custom-cloud.hc")
            "hexcustom" -> Resolved("hexcustom",hex!!,"Hex Custom Cloud","hexcm","hex-custom-cloud.hexcm")
            "mnr" -> Resolved("mnr",mnr!!,"MNR Tunnel Plus","stp","mnr-tunnel-plus.stp")
            "tunneltweak" -> Resolved("tunneltweak",tweak!!,
                "Tunneltweak Cloud","tut","tunneltweak-cloud.tut")
            "ehi" -> Resolved("ehi",injector(value)!!,"HTTP Injector Cloud","ehi","http-injector-cloud.ehi")
            else -> Resolved(selected,value,remote!!.name,remote.suffix,
                "cloud-"+remote.suffix+"."+remote.suffix)
        }
    }
}
