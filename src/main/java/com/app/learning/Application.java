package com.app.learning;


import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Application {
    private static Logger logger = Logger.getLogger(Application.class.getName());

    public static void main(String[] args) throws EncryptionException {

        try (InputStream inputStream = Application.class.getResourceAsStream("/app.properties")) {
            Properties properties = new Properties();
            properties.load(inputStream);
            EncryptionHelper encryptionHelper = new EncryptionHelper(properties);
            logger.log(Level.INFO, "Initializing helper");
            encryptionHelper.init();
            logger.log(Level.INFO, "Performing encryption");
            encryptionHelper.performEncryption();
            logger.log(Level.INFO, "Performing decryption");
            encryptionHelper.performDecryption();
        } catch (IOException e) {
            throw new EncryptionException(e);
        }


    }


}
