package com.auth.security;

import com.auth.constants.AuthConstants;
import com.auth.payload.UserDetailsResponse;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Token Generator and user details provider class
 *
 * @author Bhupinder Singh
 */
@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);

    @Value("${auth.jwtIssuer}")
    private String jwtIssuer;

    @Value("${auth.accessjwtExpirationInMs}")
    private int accessjwtExpirationInMs;

    @Value("${auth.refreshJwtExpirationInMs}")
    private int refreshJwtExpirationInMs;

    @Value("${auth.alias}")
    private String alias;

    @Value("${auth.certificate}")
    private String certificate;

    @Value("${auth.storePassword}")
    private String storePassword;

    @Value("${auth.keyPassword}")
    private String keyPassword;



    public String generateAccessToken(Authentication authentication) throws Exception {

        KeyStore keystore = getKeyStore();

        Key key = keystore.getKey(alias, keyPassword.toCharArray());
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + accessjwtExpirationInMs);
        final String authorities = userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        Map<String, Object> claims = new HashMap<>();
        claims.put(AuthConstants.ROLES_KEY, authorities);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setIssuer(jwtIssuer)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.RS256, key)
                .compact();
    }

    public String generateRefreshToken(Authentication authentication) throws Exception {
        KeyStore keystore = getKeyStore();

        Key key = keystore.getKey(alias, keyPassword.toCharArray());

        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshJwtExpirationInMs);
        final String authorities = userPrincipal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        Map<String, Object> claims = new HashMap<>();
        claims.put(AuthConstants.ROLES_KEY, authorities);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setIssuer(jwtIssuer)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.RS256, key)
                .compact();
    }

    public String getUserNameFromJWT(String token) throws Exception {
        Claims claims = Jwts.parser()
                .setSigningKey(getPublicKey())
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public UserDetailsResponse getUserNameAndRolesFromJWT(String token) throws Exception {
        Claims claims = Jwts.parser()
                .setSigningKey(getPublicKey())
                .parseClaimsJws(token)
                .getBody();

        return new UserDetailsResponse(claims.getSubject() , claims.get(AuthConstants.ROLES_KEY).toString());
    }

    public boolean validateToken(String authToken) throws Exception {
        try {
            Jwts.parser().setSigningKey(getPublicKey()).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
            throw new SignatureException("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
            throw new MalformedJwtException("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
            throw new ExpiredJwtException(null, null, "Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
            throw new UnsupportedJwtException("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
            throw new IllegalArgumentException("JWT claims string is empty.");
        }
    }

    private PublicKey getPublicKey() throws Exception {
        Certificate cert = getKeyStore().getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        return publicKey;
    }

    private KeyStore getKeyStore() throws Exception {
        ClassPathResource resource = new ClassPathResource(certificate);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(resource.getInputStream(), storePassword.toCharArray());
        return keystore;
    }
}
