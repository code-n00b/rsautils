# RSAUtils
a java two-way authentication use JKS file
### Generate Keystore
keytool -genkey -alias alias -keyalg RSA  -keystore test.keystore  -validity 1830  -keysize 2048  -storepass  password -keypass password -dname "CN=test,OU=test,O=test,L=test,ST=test,C=test" 
### Generate Certificate
keytool -export -alias alias -keystore test.keystore -file test.cer

### client
![](https://ww1.sinaimg.cn/large/a6214fe3gy1fwyfq51lroj20a10f0q31.jpg)

### server
![](https://ww1.sinaimg.cn/large/a6214fe3gy1fx5jtmzw6bj20pt0dsaa6.jpg)
