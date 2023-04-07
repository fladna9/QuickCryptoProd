package net.fladnag.AES.messages;
import org.bouncycastle.util.encoders.Base64;
import java.nio.charset.StandardCharsets;

public class QuickEncryptedMessage {
    public int staticKeyVersion = 1;
    public byte[] nonce;
    public byte[] encryptedMessage;

    public QuickEncryptedMessage(int staticKeyVersion, byte[] nonceBytes, byte[] encryptedMessage){
        this.staticKeyVersion = staticKeyVersion;
        this.nonce = nonceBytes;
        this.encryptedMessage = encryptedMessage;
    }

    public QuickEncryptedMessage(String encrypted) {
        String[] parts = encrypted.split(";");
        if (parts.length != 3)
            throw new ExceptionInInitializerError("Not a formatted payload");
        staticKeyVersion = Integer.parseInt(parts[0]);
        nonce = Base64.decode(parts[1]);
        encryptedMessage = Base64.decode(parts[2]);
    }

    public String genEncodedEncryptedPayload() {
        if(staticKeyVersion <= 0 || nonce == null || encryptedMessage == null)
            throw new ExceptionInInitializerError("Cannot encrypt: missing key, nonce or message");
        return staticKeyVersion + ";" +
                new String(Base64.encode(nonce), StandardCharsets.UTF_8) + ";" +
                new String(Base64.encode(encryptedMessage),StandardCharsets.UTF_8);
    }
}
