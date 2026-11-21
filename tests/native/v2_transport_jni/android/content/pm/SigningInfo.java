package android.content.pm;
public class SigningInfo {
    public Signature[] current;
    public Signature[] getApkContentsSigners(){return current;}
}
