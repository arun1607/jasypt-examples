package com.app.learning;

import org.apache.commons.lang3.StringUtils;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptionHelper {

    private static Logger logger = Logger.getLogger(EncryptionHelper.class.getName());

    private File sourceFile;
    private File targetFile;
    private File decryptedFile;
    private PBEParameterSpec pbeParameterSpec;
    private byte[] saltBytes;
    private String charset = Charset.defaultCharset().displayName();
    private Properties properties;
    private String encryptionAlgoName;
    private PBEKeySpec pbeKeySpec;

    public EncryptionHelper(final Properties properties) {
        this.properties = properties;
    }


    public void init() throws EncryptionException {

        try {
            final String sourceFileName = properties.getProperty("encryption.source.file.name");
            final String encryptedFileName = properties.getProperty("encryption.target.file.name");
            final String decryptedFileName = properties.getProperty("encryption.application.file.name");

            final String userHome = System.getProperty("user.home");

            sourceFile = new File(userHome, sourceFileName);
            if (!Files.exists(sourceFile.toPath())) {
                throw new IllegalArgumentException("Source file should be present");
            }
            targetFile = new File(userHome, encryptedFileName);

            if (!Files.exists(targetFile.toPath())) {
                Files.createFile(targetFile.toPath());
            }
            decryptedFile = new File(userHome, decryptedFileName);

            if (!Files.exists(decryptedFile.toPath())) {
                Files.createFile(decryptedFile.toPath());
            }

            final String salt = properties.getProperty("encryption.salt");

            if (StringUtils.isBlank(salt)) {
                throw new IllegalArgumentException("Salt value can nto be empty");
            }

            final String password = properties.getProperty("encryption.password");

            if (StringUtils.isBlank(password)) {
                throw new IllegalArgumentException("password value can nto be empty");
            }


            saltBytes = salt.getBytes(charset);

            pbeParameterSpec = new PBEParameterSpec(saltBytes, 100);

            pbeKeySpec = new PBEKeySpec(password.toCharArray());

        } catch (IOException e) {
            throw new EncryptionException(e);
        }

    }

    public void performEncryption() throws EncryptionException {
        try (
                FileInputStream inFile = new FileInputStream(sourceFile);
                FileOutputStream outFile = new FileOutputStream(targetFile);
        ) {

            logger.log(Level.INFO, String.format("Using %s algorithm for encryption", encryptionAlgoName));
            EncryptionAlgorithm encryptionAlgorithm = getAlgoName();

            final String algorithmName = encryptionAlgorithm.getAlgorithmName();
            final Provider provider = encryptionAlgorithm.getProvider();

            SecretKeyFactory secretKeyFactory;

            if (provider != null) {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName, provider);
            } else {
                secretKeyFactory = SecretKeyFactory.getInstance(algorithmName);
            }
            Cipher cipher;

            if (provider != null) {
                cipher = Cipher.getInstance(algorithmName, provider);
            } else {
                cipher = Cipher.getInstance(algorithmName);
            }
            final SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);

            outFile.write(saltBytes);

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

            outFile.flush();

        } catch (BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IOException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new EncryptionException("Error occurred in encryption", e);
        }

    }

    public void performDecryption() {
        for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
            try (FileInputStream fis = new FileInputStream(targetFile);
                 FileOutputStream fos = new FileOutputStream(decryptedFile)) {

                byte[] salt = new byte[saltBytes.length];
                fis.read(salt);

                final String algorithmName = encryptionAlgorithm.getAlgorithmName();
                final Provider provider = encryptionAlgorithm.getProvider();

                SecretKeyFactory secretKeyFactory;

                if (provider != null) {
                    secretKeyFactory = SecretKeyFactory.getInstance(algorithmName, provider);
                } else {
                    secretKeyFactory = SecretKeyFactory.getInstance(algorithmName);
                }
                Cipher cipher;

                if (provider != null) {
                    cipher = Cipher.getInstance(algorithmName, provider);
                } else {
                    cipher = Cipher.getInstance(algorithmName);
                }

                logger.log(Level.INFO, String.format("Using %s algorithm for decryption", algorithmName));

                final SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

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
                performCleanup();
                break;
            } catch (InvalidKeyException | InvalidKeySpecException | BadPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | IOException | NoSuchPaddingException | NoSuchAlgorithmException e) {
                logger.log(Level.SEVERE, "Error occurred", e);
            }
        }
    }

    private void performCleanup() throws IOException {
        Files.deleteIfExists(targetFile.toPath());
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
