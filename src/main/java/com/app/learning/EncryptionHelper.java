package com.app.learning;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.nio.charset.Charset;
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
    private final String salt = "3ncrypyt10n";
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    private PBEParameterSpec pbeParameterSpec;
    private SecretKeyFactory secretKeyFactory;
    private SecretKey secretKey;
    private PBEKeySpec pbeKeySpec;
    private byte[] saltBytes;
    private String charset = Charset.defaultCharset().displayName();


    public void init() throws IOException {

        if (!Files.exists(sourceFile.toPath())) {
            Files.createFile(sourceFile.toPath());
        }
        if (!Files.exists(targetFile.toPath())) {
            Files.createFile(targetFile.toPath());
        }
        pbeKeySpec = new PBEKeySpec(password.toCharArray());
        saltBytes = new byte[16];
        Random random = new Random();
        random.nextBytes(saltBytes);

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
            logger.log(Level.INFO, String.format("Using %s algorithm for encryption", algorithmName));
            if (provider != null) {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName, provider);
            } else {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName);
            }

            if (provider != null) {
                encryptCipher = Cipher.getInstance(algorithmName, provider);
            } else {
                encryptCipher = Cipher.getInstance(algorithmName);
            }
            final int algorithmBlockSize = encryptCipher.getBlockSize();
            if (algorithmBlockSize > 0) {
                saltBytes = generateSalt(algorithmBlockSize);
            }
            pbeParameterSpec = new PBEParameterSpec(saltBytes, 100);

            secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);

            outFile.write(saltBytes);

            byte[] input = new byte[64];
            int bytesRead;
            while ((bytesRead = inFile.read(input)) != -1) {
                byte[] output = encryptCipher.update(input, 0, bytesRead);
                if (output != null)
                    outFile.write(output);
            }

            byte[] output = encryptCipher.doFinal();
            if (output != null)
                outFile.write(output);

            inFile.close();
            outFile.flush();
        }

    }

    public byte[] generateSalt(final int lengthBytes) {
        logger.log(Level.INFO, String.format("Requested salt length is %d", lengthBytes));
        if (this.saltBytes == null) {
            try {
                this.saltBytes = this.salt.getBytes(this.charset);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalArgumentException(
                        "Invalid charset specified: " + this.charset);
            }
        }
        if (this.saltBytes.length < lengthBytes) {
            throw new IllegalArgumentException(
                    "Requested salt larger than set");
        }
        final byte[] generatedSalt = new byte[lengthBytes];
        System.arraycopy(this.saltBytes, 0, generatedSalt, 0, lengthBytes);
        return generatedSalt;
    }

    public void performDecryption() {
        {

            for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
                try (
                        FileInputStream fis = new FileInputStream(targetFile);
                        FileOutputStream fos = new FileOutputStream(applicationFile)) {
                    final String algo = encryptionAlgorithm.getAlgorithmName();
                    Provider provider = encryptionAlgorithm.getProvider();
                    logger.log(Level.INFO, String.format("Using %s algorithm for decryption", algo));
                    if (provider != null) {
                        secretKeyFactory =
                                SecretKeyFactory.getInstance(algo, provider);
                    } else {
                        secretKeyFactory = SecretKeyFactory.getInstance(algo);
                    }

                    if (provider != null) {
                        decryptCipher = Cipher.getInstance(algo, provider);
                    } else {
                        decryptCipher = Cipher.getInstance(algo);
                    }
                    pbeParameterSpec = new PBEParameterSpec(saltBytes, 100);

                    secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

                    decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
                    byte[] in = new byte[64];
                    int read;
                    while ((read = fis.read(in)) != -1) {
                        byte[] output = decryptCipher.update(in, 0, read);
                        if (output != null)
                            fos.write(output);
                    }

                    byte[] output = decryptCipher.doFinal();
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
