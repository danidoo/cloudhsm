import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumKey;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.*;

import java.util.Base64;
import java.io.File;
import java.nio.file.Files;

/**
 * This sample demonstrates file signing
 */
public class MySign {
    /**
     * The main body will sign the contents of the file sign.txt
     * @param args
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        // Initialize the KeyStore in CloudHSM
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("Cavium");
            keyStore.load(null, null);
        } catch (KeyStoreException | CertificateException ex) {
            ex.printStackTrace();
            return;
        } catch (IOException ex) {
            ex.printStackTrace();
            return;
        }

        System.out.println("Starting...");

        // Load binary content from file
        byte [] fileBytes = null;
        try {
            String fileName = "sign.txt";
            File file = new File(fileName);
            fileBytes = Files.readAllBytes(file.toPath());
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }

        // Execute the signing process
        try {
                doSign((PrivateKey) keyStore.getKey("signing_key", null), fileBytes);
                } catch (NoSuchAlgorithmException ex) {
                    ex.printStackTrace();
                    return;
                } catch (UnrecoverableKeyException | KeyStoreException ex) {
                    ex.printStackTrace();
                    return;
                }

        System.out.println("Work completed");
    }

    /**
     * Sign the binary content using the key provided.
     * @param signingKey
     * @param toSign
     */
    private static void doSign(PrivateKey signingKey, byte [] toSign) {

        try {
            Signature signatureInstance = Signature.getInstance("SHA256withRSA", "Cavium");
            signatureInstance.initSign(signingKey);
            signatureInstance.update(toSign);
            byte[] signature = signatureInstance.sign();
            System.out.println("signature size: " + signature.length);
            System.out.println("The signature Output is:");
            System.out.println(Base64.getEncoder().encodeToString(signature));
        } catch (SignatureException ex) {
            ex.printStackTrace();
        } catch (NoSuchProviderException | InvalidKeyException | NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}