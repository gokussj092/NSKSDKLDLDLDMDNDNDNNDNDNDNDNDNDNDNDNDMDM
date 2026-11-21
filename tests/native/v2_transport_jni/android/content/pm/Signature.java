package android.content.pm;
public class Signature {
    private final byte[] data;
    public Signature(byte[] data){this.data=data.clone();}
    public byte[] toByteArray(){return data.clone();}
}
