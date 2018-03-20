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
import java.security.spec.InvalidKeySpecException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptionHelper {

    private static Logger logger = Logger.getLogger(EncryptionHelper.class.getName());

    private File sourceFile;
    private File targetFile;
    private File decryptedFile;
    private Cipher cipher;
    private PBEParameterSpec pbeParameterSpec;
    private SecretKey secretKey;
    private byte[] saltBytes;
    private String charset = Charset.defaultCharset().displayName();
    private Properties properties;
    private String encryptionAlgoName;

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

            final PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());

            encryptionAlgoName = properties.getProperty("encryption.algoName");

            saltBytes = salt.getBytes(charset);


            final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(encryptionAlgoName);

            cipher = Cipher.getInstance(encryptionAlgoName);

            pbeParameterSpec = new PBEParameterSpec(saltBytes, 100);

            secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new EncryptionException(e);
        }

    }

    public void performEncryption() throws EncryptionException {
        try (
                FileInputStream inFile = new FileInputStream(sourceFile);
                FileOutputStream outFile = new FileOutputStream(targetFile);
        ) {

            logger.log(Level.INFO, String.format("Using %s algorithm for encryption", encryptionAlgoName));


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

        } catch (BadPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IOException | IllegalBlockSizeException e) {
            throw new EncryptionException("Error occurred in encryption", e);
        }

    }

    public void performDecryption() {
        try (FileInputStream fis = new FileInputStream(targetFile);
             FileOutputStream fos = new FileOutputStream(decryptedFile)) {

            byte[] salt = new byte[saltBytes.length];
            fis.read(salt);
            logger.log(Level.INFO, String.format("Using %s algorithm for decryption", encryptionAlgoName));
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
        } catch (InvalidKeyException | BadPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | IOException e) {
            logger.log(Level.SEVERE, "Error occurred", e);
        }
    }
}
