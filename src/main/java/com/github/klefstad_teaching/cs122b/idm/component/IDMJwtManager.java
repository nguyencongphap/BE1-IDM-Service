package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    private final IDMServiceConfig serviceConfig;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();
        this.serviceConfig = serviceConfig;
    }

    private SignedJWT buildAndSignJWT(JWTClaimsSet claimsSet)
        throws JOSEException
    {
        // Build a JWSHeader
        JWSHeader header =
            new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                    .keyID(jwtManager.getEcKey().getKeyID())
                    .type(JWTManager.JWS_TYPE)
                    .build();

        // Build a SignedJWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());

        return signedJWT;
    }

    private void verifyJWT(SignedJWT jwt)
        throws JOSEException, BadJOSEException
    {
        // Verifying that the token is valid and issued by us
        jwt.verify(jwtManager.getVerifier());
        // Checking that the claims are consistent with what we expect by calling
        jwtManager.getJwtProcessor().process(jwt, null);
    }

    public String buildAccessToken(User user) {
        // Build a JWTClaimsSet
        Instant currentTime = Instant.now();

        JWTClaimsSet claimsSet =
            new JWTClaimsSet.Builder()
                    .subject(user.getEmail())
                    .expirationTime(Date.from(currentTime.plus(serviceConfig.accessTokenExpire())))
                    .issueTime(Date.from(currentTime))
                    .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                    .claim(JWTManager.CLAIM_ID, user.getId())
                    .build();
        SignedJWT signedJWT = null;
        try {
            signedJWT = buildAndSignJWT(claimsSet);
        } catch (JOSEException e) {
            e.printStackTrace();
        }

        return signedJWT.serialize();
    }

    public void verifyAccessToken(String jws)
    {
        try {
            // We are given the JWT in serialized format,
            // so we will need to use SignedJWT.parse() in order to turn it back into SignedJWT
            SignedJWT signedJWT = SignedJWT.parse(jws);

            verifyJWT(signedJWT);

            // Manually checking that the expireTime of the token has not passed.
            if (Instant.now().isAfter(signedJWT.getJWTClaimsSet().getExpirationTime().toInstant())) {
                throw new ResultError(IDMResults.ACCESS_TOKEN_IS_EXPIRED);
            }
        }
        catch (IllegalStateException | JOSEException | BadJOSEException | ParseException e) {
            throw new ResultError(IDMResults.ACCESS_TOKEN_IS_INVALID);
            // If the verify function throws an error that we know the
            // token can not be trusted and the request should not be continued
        }
    }

    public RefreshToken buildRefreshToken(User user)
    {
        Instant currentTime = Instant.now();

        RefreshToken refreshToken = new RefreshToken()
                .setToken(generateUUID().toString())
                .setUserId(user.getId())
                .setTokenStatus(TokenStatus.ACTIVE)
                .setExpireTime(currentTime.plus(serviceConfig.refreshTokenExpire()))
                .setMaxLifeTime(currentTime.plus(serviceConfig.maxRefreshTokenLifeTime()));

        return refreshToken;
    }

    public boolean hasExpired(RefreshToken refreshToken)
    {
        return false;
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {

    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }
}
