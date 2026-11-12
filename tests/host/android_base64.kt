package android.util
object Base64 {
    const val NO_WRAP=2
    fun decode(text:String,flags:Int):ByteArray {require(flags==NO_WRAP);return java.util.Base64.getDecoder().decode(text)}
    fun encodeToString(bytes:ByteArray,flags:Int):String {require(flags==NO_WRAP);return java.util.Base64.getEncoder().encodeToString(bytes)}
}
