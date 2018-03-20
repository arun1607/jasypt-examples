package com.app.learning;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

public enum EncryptionAlgorithm {
    /**
     * Algorithm used in encryption/decryption on JVM version 1.7
     */
    JDK7("PBEWITHSHA1ANDRC2_40") {
        Provider getProvider() {
            return null;
        }
    },
    /**
     * Algorithm used in encryption/decryption on JVM version 1.8
     */
    JDK8("PBEWITHSHA1ANDRC4_128") {
        Provider getProvider() {
            return null;
        }
    },



    /**
     * Algorithm used in encryption/decryption on if unlimited jurisdiction policy jars are installed.
     * This algorithm uses BouncyCastle as encryption provider.
     */
    UNLIMITED_ACCESS("PBEWITHSHA256AND128BITAES-CBC-BC") {
        @Override
        Provider getProvider() {
            return new BouncyCastleProvider();
        }
    };


    /**
     * Represents name of algorithm associated with object.
     */
    private String algorithmName;

    /**
     * Constructor to create object of {@link EncryptionAlgorithm}
     *
     * @param algorithmName
     */
    EncryptionAlgorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns name of algorithm.
     *
     * @return
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    abstract Provider getProvider();
}
