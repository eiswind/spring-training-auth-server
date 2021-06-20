package de.eiswind.training.spring.authserver.config;

import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.UUID;

// tag::snip1[]
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("news-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/news-client-oidc")
                .scope(OidcScopes.OPENID)
                .clientSettings(clientSettings -> clientSettings.requireUserConsent(true))
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
    // end::snip1[]

    // tag::snip2[]
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return new ProviderSettings().issuer("http://127.0.0.1:9000");
    }
    // end::snip2[]

    // tag::snip3[]
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }



    public static RSAKey generateRsa() {
        KeyPair keyPair;
        try {
            var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }
    // end::snip3[]


//    public static ECKey generateEc() {
//        EllipticCurve ellipticCurve = new EllipticCurve(
//                new ECFieldFp(
//                        new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853951")),
//                new BigInteger("115792089210356248762697446949407573530086143415290314195533631308867097853948"),
//                new BigInteger("41058363725152142129326129780047268409114441015993725554835256314039467401291"));
//        ECPoint ecPoint = new ECPoint(
//                new BigInteger("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
//                new BigInteger("36134250956749795798585127919587881956611106672985015071877198253568414405109"));
//        ECParameterSpec ecParameterSpec = new ECParameterSpec(
//                ellipticCurve,
//                ecPoint,
//                new BigInteger("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
//                1);
//
//        KeyPair keyPair;
//        try {
//            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
//            keyPairGenerator.initialize(ecParameterSpec);
//            keyPair = keyPairGenerator.generateKeyPair();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
//        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
//        Curve curve = Curve.forECParameterSpec(publicKey.getParams());
//        // @formatter:off
//        return new ECKey.Builder(curve, publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//        // @formatter:on
//    }
//
//    public static OctetSequenceKey generateSecret() {
//        SecretKey hmacKey;
//        try {
//            hmacKey = KeyGenerator.getInstance("HmacSha256").generateKey();
//        } catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return new OctetSequenceKey.Builder(hmacKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//    }
}
