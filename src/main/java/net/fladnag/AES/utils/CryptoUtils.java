package net.fladnag.AES.utils;
import java.security.SecureRandom;

public class CryptoUtils {
    public static final SecureRandom secureRandom = new SecureRandom();

    public static void printXmsXmx()
    {
        System.out.println("Xmx: " + Runtime.getRuntime().maxMemory());
        System.out.println("Xms: " + Runtime.getRuntime().totalMemory());
    }
    public static void nextRandomBytes(byte[] bts) {
        secureRandom.nextBytes(bts);
    }
}
