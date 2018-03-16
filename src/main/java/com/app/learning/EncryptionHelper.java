package com.app.learning;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptionHelper {

    private static Logger logger = Logger.getLogger(EncryptionHelper.class.getName());

    private final File sourceFile;
    private final File targetFile;
    private final File applicationFile;
    private final String password = "javapapers";
    private Cipher cipher;
    private PBEParameterSpec pbeParameterSpec;
    private SecretKeyFactory secretKeyFactory;
    private SecretKey secretKey;
    private PBEKeySpec pbeKeySpec;


    public void init() throws IOException {

        if (!Files.exists(sourceFile.toPath())) {
            Files.createFile(sourceFile.toPath());
        }
        if (!Files.exists(targetFile.toPath())) {
            Files.createFile(targetFile.toPath());
        }
        pbeKeySpec = new PBEKeySpec(password.toCharArray());
    }

    public EncryptionHelper(final File sourceFile, final File targetFile, final File applicationFile) {
        this.sourceFile = sourceFile;
        this.targetFile = targetFile;
        this.applicationFile = applicationFile;
    }

    public void performEncryption() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        try (
                FileInputStream inFile = new FileInputStream(sourceFile);
                FileOutputStream outFile = new FileOutputStream(targetFile);
        ) {

            EncryptionAlgorithm encryptionAlgorithm = getAlgoName();


            final Provider provider = encryptionAlgorithm.getProvider();
            final String algorithmName = encryptionAlgorithm.getAlgorithmName();
            if (provider != null) {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName, provider);
            } else {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName);
            }

            secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

            byte[] salt = new byte[8];
            Random random = new Random();
            random.nextBytes(salt);

            pbeParameterSpec = new PBEParameterSpec(salt, 100);
            if (provider != null) {
                cipher = Cipher.getInstance(algorithmName, provider);
            } else {
                cipher = Cipher.getInstance(algorithmName);
            }
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
            outFile.write(salt);

            byte[] input = new byte[64];
            int bytesRead;
            while ((bytesRead = inFile.read(input)) != -1) {
                byte[] output = cipher.update(input, 0, bytesRead);
                if (output != null)
                    outFile.write(output);
            }

            byte[] output = cipher.doFinal();
            if (output != null)
                outFile.write(output);

            inFile.close();
            outFile.flush();
        }

    }

    public void performDecryption() {
        {

            for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
                try (
                        FileInputStream fis = new FileInputStream(targetFile);
                        FileOutputStream fos = new FileOutputStream(applicationFile)) {
                    final String algo = encryptionAlgorithm.getAlgorithmName();
                    Provider provider = encryptionAlgorithm.getProvider();
                    if (provider != null) {
                        secretKeyFactory =
                                SecretKeyFactory.getInstance(algo, provider);
                    } else {
                        secretKeyFactory = SecretKeyFactory.getInstance(algo);
                    }

                    secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
                    if (provider != null) {
                        cipher = Cipher.getInstance(algo, provider);
                    } else {
                        cipher = Cipher.getInstance(algo);
                    }
                    cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
                    byte[] in = new byte[64];
                    int read;
                    while ((read = fis.read(in)) != -1) {
                        byte[] output = cipher.update(in, 0, read);
                        if (output != null)
                            fos.write(output);
                    }

                    byte[] output = cipher.doFinal();
                    if (output != null)
                        fos.write(output);

                    fos.flush();
                    break;
                } catch (InvalidKeySpecException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | IOException e) {
                    logger.log(Level.SEVERE, "Error occurred", e);
                }
            }

        }
    }

    private EncryptionAlgorithm getAlgoName() {
        EncryptionAlgorithm encryptionAlgorithm = null;
        try {
            int maxAllowedKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            if (maxAllowedKeyLength <= 128) {
                if (System.getProperty("java.version").startsWith("1.7")) {
                    logger.log(Level.INFO, String.format("Using algorithm : %s for JDK 1.7", EncryptionAlgorithm.JDK7.getAlgorithmName()));
                    encryptionAlgorithm = EncryptionAlgorithm.JDK7;
                } else {
                    logger.log(Level.INFO, String.format("Using algorithm : %s for JDK 1.8+", EncryptionAlgorithm.JDK8.getAlgorithmName()));
                    encryptionAlgorithm = EncryptionAlgorithm.JDK8;
                }
            } else {
                encryptionAlgorithm = EncryptionAlgorithm.UNLIMITED_ACCESS;
                logger.log(Level.INFO, String.format("JCE Unlimited strength jurisdiction policy jars detected. Using algorithm : %s", encryptionAlgorithm.getAlgorithmName()));
            }
        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Unable to determine encryption algorithm", e);
        }
        return encryptionAlgorithm;
    }
}
