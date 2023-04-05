package net.fladnag.AES.utils;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

public class CryptoUtils {
    public static final SecureRandom secureRandom = new SecureRandom();

    public static void printXmsXmx()
    {
        System.out.println("Xmx: " + Runtime.getRuntime().maxMemory());
        System.out.println("Xms: " + Runtime.getRuntime().totalMemory());
    }
    public static final void nextRandomBytes(byte[] bts) {
        secureRandom.nextBytes(bts);
    }
}
