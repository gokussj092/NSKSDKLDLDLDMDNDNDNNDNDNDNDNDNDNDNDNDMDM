package android.content;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
/** JVM-only framework double; never an Android APK source. */
public class Context {
    public String packageName="com.ghostdeveloper.spdecode";
    public ApplicationInfo applicationInfo=new ApplicationInfo();
    public PackageManager packageManager=new PackageManager();
    public String getPackageName(){return packageName;}
    public ApplicationInfo getApplicationInfo(){return applicationInfo;}
    public PackageManager getPackageManager(){return packageManager;}
}
