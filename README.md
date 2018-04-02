#### Overview

Sample app to demonstrate encryption and decryption. The encryption algorithm will be decided based on available 
algorithm for installed JDK. During decryption all possible algorithm will be used. 

This application will use three files to read/write property to encrypt, encrypted property and
unencrypted property. These files will be created in user's home folder. The file names can be configured
using [property file](src/main/resources/app.properties)

The password and salt values can be configured in [property file](src/main/resources/app.properties)

This application uses [Bouncy Castle Provider](https://www.bouncycastle.org/java.html) if unlimited policy is detected. In order to use [Bouncy Castle Provider](https://www.bouncycastle.org/java.html),
it should be added in JDK. Please refer [this](http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation) and [this](https://docs.oracle.com/cd/E19830-01/819-4712/ablsc/index.html) for 
[Bouncy Castle Provider](https://www.bouncycastle.org/java.html) installation.
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