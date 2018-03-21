#### Overview

Sample app to demonstrate encryption and decryption. The encryption algorithm will be decided based on available 
algorithm for installed JDK. During decryption all possible algorithm will be used. 

This application will use three files to read/write property to encrypt, encrypted property and
unencrypted property. These files will be created in user's home folder. The file names can be configured
using [property file](src/main/resources/app.properties)

The password and salt values cab ne configured in [property file](src/main/resources/app.properties)

##### Running the application
###### Windows

```
gradlew.bat clean shadowJar

java -jar build\libs\encryption-sample-0.0.1-all.jar

```

###### Mac/Linux
```
./gradlew clean shadowJar

java -jar build/libs/encryption-sample-0.0.1-all.jar

```