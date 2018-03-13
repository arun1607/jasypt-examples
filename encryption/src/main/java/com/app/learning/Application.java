package com.app.learning;

import org.apache.commons.configuration2.Configuration;
import org.apache.commons.configuration2.FileBasedConfiguration;
import org.apache.commons.configuration2.PropertiesConfiguration;
import org.apache.commons.configuration2.builder.FileBasedConfigurationBuilder;
import org.apache.commons.configuration2.builder.fluent.Parameters;
import org.apache.commons.lang3.StringUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.EnvironmentStringPBEConfig;
import org.jasypt.properties.PropertyValueEncryptionUtils;
import org.jasypt.salt.StringFixedSaltGenerator;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;

import java.io.File;
import java.nio.file.Files;

@SpringBootApplication
public class Application {
    static {
        System.setProperty("APP_ENCRYPTION_PASSWORD", "3aee48e4e5c484e7faaa9090529937f48e2fbcdfed4eac430ba82cda25615944");
        System.setProperty("APP_ENCRYPTION_SALT", "b07133987d64ba799f274dd241f819573b6421d859c016ba6b560146715e9551");
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public CommandLineRunner encryptor(ApplicationContext ctx) {
        return args -> {

            String userHome = System.getProperty("user.home");

            File propertyFile = new File(userHome, "sample.properties");
            if (!Files.exists(propertyFile.toPath())) {
                Files.createFile(propertyFile.toPath());
            }
            Parameters params = new Parameters();
            FileBasedConfigurationBuilder<FileBasedConfiguration> builder =
                    new FileBasedConfigurationBuilder<FileBasedConfiguration>(PropertiesConfiguration.class)
                            .configure(params.properties()
                                    .setFile(propertyFile));

            Configuration config = builder.getConfiguration();
            String adminPassword = config.getString("adminPassword");
            StringEncryptor stringEncryptor = ctx.getBean("jasyptStringEncryptor", StringEncryptor.class);
            if (StringUtils.isBlank(adminPassword)) {
                config.addProperty("adminPassword", PropertyValueEncryptionUtils.encrypt("admin@123", stringEncryptor));
                builder.save();
            }
        };
    }

    @Bean("jasyptStringEncryptor")
    public StringEncryptor stringEncryptor(EnvironmentStringPBEConfig encryptionConfig) {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setConfig(encryptionConfig);
        return encryptor;
    }

    @Bean("encryptionConfig")
    public EnvironmentStringPBEConfig getConfig() {
        EnvironmentStringPBEConfig environmentStringPBEConfig = new EnvironmentStringPBEConfig();
        environmentStringPBEConfig.setPasswordSysPropertyName("APP_ENCRYPTION_PASSWORD");
        environmentStringPBEConfig.setKeyObtentionIterations(1000);
        environmentStringPBEConfig.setAlgorithm("PBEWITHSHA1ANDRC4_128");
        environmentStringPBEConfig.setKeyObtentionIterations("1000");
        environmentStringPBEConfig.setPoolSize("1");
        environmentStringPBEConfig.setProviderName("SunJCE");
        String appEncryptionSalt = System.getProperty("APP_ENCRYPTION_SALT");
        if (StringUtils.isNoneEmpty(appEncryptionSalt)) {
            StringFixedSaltGenerator saltGenerator = new StringFixedSaltGenerator(appEncryptionSalt);
            environmentStringPBEConfig.setSaltGenerator(saltGenerator);
        }
        return environmentStringPBEConfig;
    }

}
