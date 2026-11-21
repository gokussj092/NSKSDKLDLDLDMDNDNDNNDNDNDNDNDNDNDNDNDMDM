package com.ghostdeveloper.spdecode.cloud;

import android.content.Context;
import android.content.pm.Signature;
import android.os.Build;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Calls the production JNI verifier with synthetic framework results. */
final class ReleaseSignerContract {
    interface Verifier { boolean verify(Context ctx,String pkg,String upload,String play,boolean debug); }
    private static final String PACKAGE="com.ghostdeveloper.spdecode";
    private static final Signature UPLOAD=new Signature(new byte[]{1,2,3});
    private static final Signature PLAY=new Signature(new byte[]{4,5,6});
    private static final Signature HYBRID_CLASSICAL=new Signature(new byte[]{7,8,9});
    private static final Signature PQC=new Signature(new byte[]{10,11,12});
    private static final Signature UNKNOWN=new Signature(new byte[]{13,14,15});
    private static int cases;
    private static String hash(Signature value)throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.toByteArray()));
    }
    private static Context context(Signature... current){
        Context ctx=new Context();
        ctx.packageManager.info.signingInfo.current=current;
        ctx.packageManager.info.signatures=current;
        return ctx;
    }
    private static void check(boolean value,String reason){
        if(!value)throw new AssertionError(reason);
        cases++;
    }
    static void run(Verifier verifier)throws Exception {
        String upload=hash(UPLOAD),play=hash(PLAY);
        for(int sdk:new int[]{26,28,33,36,37}){
            Build.VERSION.SDK_INT=sdk;
            check(verifier.verify(context(UPLOAD),PACKAGE,upload,play,false),"Telegram signer rejected on API "+sdk);
            check(verifier.verify(context(PLAY),PACKAGE,upload,play,false),"Classic Play signer rejected on API "+sdk);
            check(!verifier.verify(context(UNKNOWN),PACKAGE,upload,play,false),"Unknown signer accepted on API "+sdk);
        }
        Build.VERSION.SDK_INT=37;
        Context hybrid=context(PQC);
        hybrid.packageManager.verifiedHistory=new Signature[]{PLAY,HYBRID_CLASSICAL,PQC};
        check(verifier.verify(hybrid,PACKAGE,upload,play,false),"Android 17 verified Play-to-PQC rotation rejected");
        check(hybrid.packageManager.lineageQueries==1,"Android-verified lineage not consulted");
        Context rotated=context(HYBRID_CLASSICAL);
        rotated.packageManager.verifiedHistory=new Signature[]{PLAY,HYBRID_CLASSICAL};
        Build.VERSION.SDK_INT=28;
        check(verifier.verify(rotated,PACKAGE,upload,play,false),"Verified classic rotation rejected");
        Build.VERSION.SDK_INT=37;
        Context unlinked=context(PQC);
        unlinked.packageManager.verifiedHistory=new Signature[]{HYBRID_CLASSICAL,PQC};
        check(!verifier.verify(unlinked,PACKAGE,upload,play,false),"Unrelated hybrid lineage accepted");
        Context uploadRotation=context(UNKNOWN);
        uploadRotation.packageManager.verifiedHistory=new Signature[]{UPLOAD,UNKNOWN};
        check(!verifier.verify(uploadRotation,PACKAGE,upload,play,false),"Upload-only history broadened Play trust");
        Context multi=context(PLAY,UNKNOWN);
        multi.packageManager.verifiedHistory=new Signature[]{PLAY,UNKNOWN};
        check(!verifier.verify(multi,PACKAGE,upload,play,false),"Unknown co-signer accepted");
        check(multi.packageManager.lineageQueries==0,"Multi-signer rejection used historical trust");
        check(verifier.verify(context(PLAY,UPLOAD),PACKAGE,upload,play,false),"All-pinned co-signers rejected");
        check(!verifier.verify(context(),PACKAGE,upload,play,false),"Empty signer set accepted");
        check(!verifier.verify(context(PQC),PACKAGE,upload,"malformed",false),"Malformed Play anchor accepted");
        Context debuggable=context(PLAY);debuggable.applicationInfo.flags=2;
        check(!verifier.verify(debuggable,PACKAGE,upload,play,false),"Debuggable release accepted");
        Context wrongPackage=context(PLAY);wrongPackage.packageName="repacked.example";
        check(!verifier.verify(wrongPackage,PACKAGE,upload,play,false),"Wrong package accepted");
        Context broken=context(PLAY);broken.packageManager.failLookup=true;
        check(!verifier.verify(broken,PACKAGE,upload,play,false),"Framework exception accepted");
        Context brokenLineage=context(PQC);brokenLineage.packageManager.failLineage=true;
        check(!verifier.verify(brokenLineage,PACKAGE,upload,play,false),"Lineage exception accepted");
        check(verifier.verify(context(PLAY),PACKAGE,upload,play,false),"JNI pending exception leaked into next call");
        check(!verifier.verify(null,PACKAGE,upload,play,false),"Null context accepted in release");
        check(verifier.verify(null,PACKAGE,"","",true),"Existing debug semantics changed");
        System.out.println("PASS "+cases+" release signer JNI cases (synthetic framework; not a Play-device test)");
    }
}
