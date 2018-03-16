package com.app.learning;


import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Application {
    private static Logger logger = Logger.getLogger(Application.class.getName());

    public static void main(String[] args) throws Exception {
        String userHome = System.getProperty("user.home");
        File sourceFile = new File(userHome, "plainfile.txt");
        File targetFile = new File(userHome, "plainfile.des");
        File applicationFile = new File(userHome, "plainfile_decrypted.txt");
        EncryptionHelper encryptionHelper = new EncryptionHelper(sourceFile, targetFile, applicationFile);
        logger.log(Level.INFO, "Initializing helper");
        encryptionHelper.init();
        logger.log(Level.INFO, "Performing encryption");
        encryptionHelper.performEncryption();
        logger.log(Level.INFO, "Performing decryption");
        encryptionHelper.performDecryption();


    }


}
