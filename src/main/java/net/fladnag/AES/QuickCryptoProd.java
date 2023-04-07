package net.fladnag.AES;
import net.fladnag.AES.crypto.AESTool;
import net.fladnag.AES.crypto.keychain.QuickKeychain;
import net.fladnag.AES.messages.QuickEncryptedMessage;
import net.fladnag.AES.utils.CryptoUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import static java.lang.Math.abs;

public class QuickCryptoProd {
    private int keyIndex = 1;
    private static QuickCryptoProd _instance;
    private QuickKeychain keychain;
    private QuickEncryptedMessage encryptedMessage;

    private QuickCryptoProd() {}
    public static QuickCryptoProd getInstance() {
        if (_instance == null) {
            Security.addProvider(new BouncyCastleProvider());
            _instance = new QuickCryptoProd();
        }
        return _instance;
    }

    public void setKeyIndex(int index) {
        keyIndex = index;
    }

    public void generateKeychain(String passphrase) {
        this.keychain = new QuickKeychain(passphrase);
    }

    public String encryptMessage(String message) throws Exception {
        encryptedMessage = new QuickEncryptedMessage(
                keyIndex,
                keychain.generateNewNonce(),
                AESTool.encrypt(
                        message.getBytes(StandardCharsets.UTF_8),
                        keychain.getCurrentKey(),
                        keychain.getCurrentIV()));
        return encryptedMessage.genEncodedEncryptedPayload();
    }

    public String decryptMessage(String payload) throws Exception {
        encryptedMessage = new QuickEncryptedMessage(payload);
        assert(keyIndex == encryptedMessage.staticKeyVersion);
        keychain.setNewNonce(encryptedMessage.nonce);
        return new String(AESTool.decrypt(encryptedMessage.encryptedMessage, keychain.getCurrentKey(), keychain.getCurrentIV()), StandardCharsets.UTF_8);
    }

    public static void main (String [] args) throws Exception {
        System.out.println("Small tests for QuickCryptoProd");
        CryptoUtils.printXmsXmx();
        demo();
        bench();
    }

    public static void demo () throws Exception {
        System.out.println("DEMO");
        System.out.println("---------------");
        // DEMO VECTORS
        String message = "Lorem Salu bissame ! Wie geht's les samis ? Hans apporte moi une Wurschtsalad avec un " +
                "picon bitte, s'il te plaît. Voss ? Une Carola et du Melfor ? Yo dû, espèce de Knäckes, ch'ai dit un " +
                "picon ! Hopla vous savez que la mamsell Huguette, la miss Miss Dahlias du messti de Bischheim était " +
                "au Christkindelsmärik en compagnie de Richard Schirmeck (celui qui a un blottkopf), le mari de " +
                "Chulia Roberstau, qui lui trempait sa Nüdle dans sa Schneck ! Yo dû, Pfourtz ! Ch'espère qu'ils " +
                "avaient du Kabinetpapier, Gal !";

        String passPhrase = "AZERTYUIOPQSDFGHJKLMWXCVBN123456";

        String chiffre = "1;vX/jXvJLU6izLKbPH1o6VjmyBCMl3PNZsOgcHgontvw=;xowI3dOtk86iqJCFATBU0H1x/Dp+7THR+YJdNw0i1GiJ" +
                "PQW4hbEVdTr5ST4mFFxKkL6KsdfsO6QC80W15saf/mmGCI2I6rtZeSu70Cw+ENoZdvDfAlr2oy1lyOoMLKWipkGqAAvHge3oJjur" +
                "OPhfTnaeDD5DWQl9HFI3YFFTS47+KE56DR8rDqoiG3T2O+7SJi+7S5dzkX83CSdJQPYLpIdAH2vC4bKsb4POxd7R1/ODuJ/Aw13H" +
                "+6Xdku3I17+BEPE+lTyBVhw8GB92FDIBwSo7iKKMUxYlCXcpIW732m0UNNHMPytWJIjrbklWILbXlIUODDVxr6hyzNLycRYnpaCC" +
                "Q2QddbDRdxuYBX39oz8BA4GXDjFRnM97nMjW6mKA/AAuSsyCKFw268qn33WkaiwnRqkpgEww3iEugJXj9sQ+5OM4AizuWWS5coiy" +
                "++qtthadUOuo55DPR6Ie2L7EJSiOdKb9Ns/X1WPJ1eA23QohyYT9RJ76YwFa4UZMzBS2RFNX757tk0YUkK6eh40ZDgIfPFTep7pX" +
                "9S7HlwM8fGfem/fMNokvtbV9WEkr3I4TXgP+o2FDg10U3Lm/7cKCkklHFAvy9URFNcs+fRVbaDzaoZ3MK++aSiYa8xVq8fTZV2UK" +
                "b7iRlRtgBP4eIDJP9vhy66ti/Hsno/bqKw7s0msPLuSlsQc/67Y7DmUDFkp8tgd8tus=";

        // INITIALISATION de QCP
        QuickCryptoProd quickCryptoProdInstance = QuickCryptoProd.getInstance();
        quickCryptoProdInstance.generateKeychain(passPhrase);


        // CHIFFREMENT
        String encrypted = quickCryptoProdInstance.encryptMessage(message);

        // AFFICHAGE VISUEL RESULTAT
        System.out.println("Chiffrement");
        System.out.println("Key        : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentKey())));
        System.out.println("IV         : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentIV())));
        System.out.println("Encrypted  : " + encrypted);


        // DECHIFFREMENT
        String result = quickCryptoProdInstance.decryptMessage(chiffre);

        // AFFICHAGE VISUEL RESULTAT
        System.out.println("Déchiffrement");
        System.out.println("Key        : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentKey())));
        System.out.println("IV         : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentIV())));
        System.out.println("Clair      : " + result);
        System.out.println("---------------");
    }

    public static void bench () throws Exception {
        try {
            System.out.println("BENCH");
            System.out.println("---------------");
            long benchCount = 1000000;
            System.out.println("Benchmarking QuickCryptoProd, " + benchCount + " rounds");

            //Setup BC provider and static keypair
            QuickCryptoProd quickCryptoProdInstance = QuickCryptoProd.getInstance();
            quickCryptoProdInstance.generateKeychain("AZERTYUIOPQSDFGHJKLMWXCVBN123456");

            String message = "Lorem Salu bissame ! Wie geht's les samis ? Hans apporte moi une Wurschtsalad avec un " +
                    "picon bitte, s'il te plaît. Voss ? Une Carola et du Melfor ? Yo dû, espèce de Knäckes, ch'ai dit un " +
                    "picon ! Hopla vous savez que la mamsell Huguette, la miss Miss Dahlias du messti de Bischheim était " +
                    "au Christkindelsmärik en compagnie de Richard Schirmeck (celui qui a un blottkopf), le mari de " +
                    "Chulia Roberstau, qui lui trempait sa Nüdle dans sa Schneck ! Yo dû, Pfourtz ! Ch'espère qu'ils " +
                    "avaient du Kabinetpapier, Gal !";

            long start = System.currentTimeMillis();
            for (int i = 0; i < benchCount; i++) {
                quickCryptoProdInstance.keychain.generateNewNonce();
                String encrypted = quickCryptoProdInstance.encryptMessage(message);

                if (benchCount >= 10 && i % (benchCount / 10) == 0) {
                    System.out.println((int) ((float) i / benchCount * 100) + "%.....");
                    //System.out.println("Key        : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentKey())));
                    //System.out.println("IV         : " + new String(Base64.encode(quickCryptoProdInstance.keychain.getCurrentIV())));
                    //System.out.println("Encrypted  : " + encrypted);
                }
            }
            long timeElapsed = System.currentTimeMillis() - start;
            System.out.println("\nApproximated Mean Execution Time: " + (float) timeElapsed / (float) benchCount + "ms");
            if(abs((float) timeElapsed / (float) benchCount) > 0.0000001)
                System.out.println("Approximate Operations per Second: " + (float) 1/((float) timeElapsed / (float) benchCount) * (float) 1000 + " OPS");
            System.out.println("---------------");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
