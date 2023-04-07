package net.fladnag.AES.crypto;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import static javax.crypto.Cipher.*;

public class AESTool {
    static {
        try {
            Security.setProperty("crypto.policy", "unlimited");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(byte[] messageToEncrypt, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, Arrays.copyOfRange(iv, 1, 8));
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        cipher.init(ENCRYPT_MODE, secretKey, gcmParameterSpec);
        return cipher.doFinal(messageToEncrypt);
    }

    public static byte[] decrypt(byte[] messageToDecrypt, byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, Arrays.copyOfRange(iv, 1, 8));
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        cipher.init(DECRYPT_MODE, secretKey, gcmParameterSpec);
        return cipher.doFinal(messageToDecrypt);
    }
}
