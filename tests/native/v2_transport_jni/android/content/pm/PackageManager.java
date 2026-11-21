package android.content.pm;
import java.security.MessageDigest;
import java.util.Arrays;
public class PackageManager {
    public PackageInfo info=new PackageInfo();
    public Signature[] verifiedHistory=new Signature[0];
    public boolean failLookup;
    public boolean failLineage;
    public int lineageQueries;
    public PackageInfo getPackageInfo(String name,int flags){
        if(failLookup)throw new IllegalStateException("synthetic PackageManager failure");
        return info;
    }
    // The history here is a test input simulating Android's verified result.
    // This double does NOT verify a real APK or a proof-of-rotation signature.
    public boolean hasSigningCertificate(String name,byte[] certificate,int type){
        lineageQueries++;
        if(failLineage)throw new IllegalStateException("synthetic lineage failure");
        if(!name.equals("com.ghostdeveloper.spdecode")||type!=1||certificate.length!=32)
            throw new AssertionError("Wrong PackageManager trust-anchor arguments");
        try {
            for(Signature signer:verifiedHistory)
                if(Arrays.equals(certificate,MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())))return true;
            return false;
        }catch(java.security.NoSuchAlgorithmException e){throw new AssertionError(e);}
    }
}
