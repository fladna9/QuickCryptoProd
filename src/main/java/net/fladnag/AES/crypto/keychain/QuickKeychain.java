package net.fladnag.AES.crypto.keychain;

import net.fladnag.AES.utils.CryptoUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class QuickKeychain {
    private int length = 32;
    private byte[] staticPassphrase;
    private byte[] currentNonce;
    private byte[] currentKey;
    private byte[] currentIV;

    public QuickKeychain(String passphrase) {
        this(Base64.decode(passphrase));
    }

    public QuickKeychain(byte[] passBytes) {
        staticPassphrase = passBytes;
        assertPassphrase();
    }

    public byte[] generateNewNonce() {
        currentNonce = new byte[32];
        CryptoUtils.nextRandomBytes(currentNonce);
        return currentNonce;
    }

    public void setNewPassphrase(String newPassphrase){
        setNewPassphrase(Base64.decode(newPassphrase));
    }
    public void setNewPassphrase(byte[] newPassphrase){
        staticPassphrase = newPassphrase;
        assertPassphrase();
    }

    public void setNewNonce(String nonce) {
        setNewNonce(Base64.decode(nonce));
    }

    public void setNewNonce(byte[] nonce) {
        currentNonce = nonce;
    }

    public byte[] getCurrentKey() throws NoSuchAlgorithmException {
        assertPassphrase(); assertNonce();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(staticPassphrase);
        md.update(currentNonce);
        currentKey = md.digest();
        return currentKey;
    }

    public byte[] getCurrentIV() throws NoSuchAlgorithmException {
        assertPassphrase(); assertNonce(); assertKey();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(currentKey);
        currentIV = md.digest();
        return currentIV;
    }

    private void assertPassphrase() {
        assert(staticPassphrase != null && staticPassphrase.length >= length);
    }
    private void assertNonce() {
        assert(currentNonce != null && currentNonce.length >= length);
    }
    private void assertKey() {
        assert(currentKey != null);
    }
}
