package com.app.learning;

import org.apache.commons.lang3.StringUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.properties.PropertyValueEncryptionUtils;
import org.jasypt.salt.StringFixedSaltGenerator;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class EncryptionHelper {

    private static Logger logger = Logger.getLogger(EncryptionHelper.class.getName());

    private File sourceFile;
    private File targetFile;
    private File decryptedFile;
    private Properties properties;
    private String password;
    private String salt;

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


            salt = properties.getProperty("encryption.salt");

            if (StringUtils.isBlank(salt)) {
                throw new IllegalArgumentException("Salt value can nto be empty");
            }
            final StringFixedSaltGenerator saltGenerator = new StringFixedSaltGenerator(salt);

            password = properties.getProperty("encryption.password");

            if (StringUtils.isBlank(password)) {
                throw new IllegalArgumentException("password value can nto be empty");
            }

        } catch (IOException e) {
            throw new EncryptionException("Problem occurred in initialization", e);
        }

    }

    public void performEncryption() throws EncryptionException {
        try (
                BufferedReader bufferedReader = new BufferedReader(new FileReader(sourceFile));
                BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(targetFile))
        ) {

            EncryptionAlgorithm encryptionAlgorithm = getAlgoName();

            final String algorithmName = encryptionAlgorithm.getAlgorithmName();

            logger.log(Level.INFO, String.format("Using %s algorithm for encryption", algorithmName));

            StringEncryptor encryptor = getEncryptor(encryptionAlgorithm);
            String textoEncrypt = bufferedReader.readLine();
            String encryptedText = null;
            if (!PropertyValueEncryptionUtils.isEncryptedValue(textoEncrypt)) {
                encryptedText = PropertyValueEncryptionUtils.encrypt(textoEncrypt, encryptor);
            }
            if (StringUtils.isNotBlank(encryptedText)) {
                bufferedWriter.write(encryptedText);
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            throw new EncryptionException("Error occurred in encryption", e);
        }

    }

    public void performDecryption() throws EncryptionException, IOException {

        try (
                BufferedReader bufferedReader = new BufferedReader(new FileReader(targetFile));
                BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(decryptedFile))
        ) {

            String encryptedText = bufferedReader.readLine();
            String decryptedText = null;
            for (EncryptionAlgorithm encryptionAlgorithm : EncryptionAlgorithm.values()) {
                final String algorithmName = encryptionAlgorithm.getAlgorithmName();
                logger.log(Level.INFO, String.format("Trying %s algorithm for decryption", algorithmName));
                StringEncryptor encryptor = getEncryptor(encryptionAlgorithm);
                try {
                    if (PropertyValueEncryptionUtils.isEncryptedValue(encryptedText)) {
                        decryptedText = PropertyValueEncryptionUtils.decrypt(encryptedText, encryptor);
                        break;
                    }
                } catch (EncryptionOperationNotPossibleException | EncryptionInitializationException ex) { // NOSONAR - This exception only required in debug level.
                    logger.log(Level.INFO, "Unable to decrypt using " + algorithmName);
                    logger.log(Level.INFO, "Trying with next available algorithm");
                }
            }

            if (StringUtils.isNotBlank(decryptedText)) {
                bufferedWriter.write(decryptedText);
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            throw new EncryptionException("Error occurred in reading writing file", e);
        }
        performCleanup();
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

    private EnvironmentStringPBEConfig getConfig(EncryptionAlgorithm encryptionAlgorithm) {
        EnvironmentStringPBEConfig environmentStringPBEConfig = new EnvironmentStringPBEConfig();
        environmentStringPBEConfig.setKeyObtentionIterations(1000);
        environmentStringPBEConfig.setAlgorithm(encryptionAlgorithm.getAlgorithmName());
        if (encryptionAlgorithm.getProvider() != null) {
            environmentStringPBEConfig.setProvider(encryptionAlgorithm.getProvider());
        }
        StringFixedSaltGenerator saltGenerator = new StringFixedSaltGenerator(salt);
        environmentStringPBEConfig.setSaltGenerator(saltGenerator);
        environmentStringPBEConfig.setPassword(password);
        return environmentStringPBEConfig;
    }

    public StringEncryptor getEncryptor(EncryptionAlgorithm encryptionAlgorithm) {

        PooledPBEStringEncryptor pooledPBEStringEncryptor = new PooledPBEStringEncryptor();
        pooledPBEStringEncryptor.setPoolSize(10);
        pooledPBEStringEncryptor.setConfig(getConfig(encryptionAlgorithm));
        return pooledPBEStringEncryptor;
    }
}
