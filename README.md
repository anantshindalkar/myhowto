# myhowto

Generate an SSL certificate in a keystore


keytool -genkeypair -alias springboot -keyalg RSA -keysize 4096 -storetype JKS -keystore springboot.jks -validity 3650 -storepass password


keytool -genkeypair -alias springboot -keyalg RSA -keysize 4096 -storetype PKCS12 -keystore springboot.p12 -validity 3650 -storepass password

keytool -list -v -keystore springboot.jks
keytool -list -v -keystore springboot.p12
keytool -importkeystore -srckeystore springboot.jks -destkeystore springboot.p12 -deststoretype pkcs12
keytool -import -alias springboot -file myCertificate.crt -keystore springboot.p12 -storepass password


client :
keytool -export -keystore springboot.p12 -alias springboot -file myCertificate.crt
keytool -importcert -file myCertificate.crt -alias springboot -keystore $JDK_HOME/jre/lib/security/cacerts



To enable HTTPS for our Spring Boot application, let's open our application.yml file (or application.properties) and define the following properties:

server:
  ssl:
    key-store: classpath:keystore.p12
    key-store-password: password
    key-store-type: pkcs12
    key-alias: springboot
    key-password: password
  port: 8443
  
  
  
create a SecurityConfig class to gather the security policies and configure the application to require a secure channel for all requests. 

@Configuration
public class SecurityConfig {

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
      .requiresChannel(channel -> 
          channel.anyRequest().requiresSecure())
      .authorizeRequests(authorize ->
          authorize.anyRequest().permitAll())
      .build();
    }

}

