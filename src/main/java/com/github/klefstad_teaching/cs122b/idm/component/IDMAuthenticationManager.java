package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;
    private final IDMServiceConfig serviceConfig;
    private final IDMJwtManager            jwtManager;

    @Autowired
    public IDMAuthenticationManager(IDMRepo repo,
                                    IDMServiceConfig serviceConfig,
                                    IDMJwtManager jwtManager)
    {
        this.repo = repo;
        this.serviceConfig = serviceConfig;
        this.jwtManager = jwtManager;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public User selectAndAuthenticateUser(String email, char[] password)
    {
        User user = null;
        try {
            user = repo.getUserByEmail(email);
        }
        catch (EmptyResultDataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }

        // get the stored salt corresponding with the email
        String storedSalt = user.getSalt();

        // Hash the given password with the stored salt corresponding with the email, encode it to string
        byte[] hashedInputPassword  = hashPassword(password, storedSalt);
        String base64EncodedHashedInputPassword = Base64.getEncoder().encodeToString(hashedInputPassword);

        if (!base64EncodedHashedInputPassword.equals(user.getHashedPassword())) {
            throw new ResultError(IDMResults.INVALID_CREDENTIALS);
        }

        UserStatus userStatusRetrieved = user.getUserStatus();
        if (userStatusRetrieved.value().equals("Locked")) {
            throw new ResultError(IDMResults.USER_IS_LOCKED);
        }
        if (userStatusRetrieved.value().equals("Banned")) {
            throw new ResultError(IDMResults.USER_IS_BANNED);
        }

        return user;
    }

    public void createAndInsertUser(String email, char[] password)
    {
        // Generate salt for user
        byte[] salt = genSalt();

        // Hash and salt password
        byte[] encodedPassword  = hashPassword(password, salt);

        // Encode both salt and saltedPassword into base64 String
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(encodedPassword);
        String base64EncodedHashedSalt = Base64.getEncoder().encodeToString(salt);

        // Assign the user_status of ACTIVE represented by Integer 1
        Integer userStatus = 1;

        repo.insertUser(email, userStatus, base64EncodedHashedSalt, base64EncodedHashedPassword);
    }

    public void insertRefreshToken(RefreshToken refreshToken)
    {
        repo.insertRefreshToken(refreshToken);
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        if (token.length() != 36) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_LENGTH);
        }

        try {
            UUID.fromString(token);
        }
        catch (IllegalArgumentException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_HAS_INVALID_FORMAT);
        }

        RefreshToken refreshToken = null;
        try {
            refreshToken = repo.getRefreshTokenByToken(token);
        }
        catch (EmptyResultDataAccessException e) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_NOT_FOUND);
        }

        if (refreshToken.getTokenStatus().value().equals(TokenStatus.EXPIRED.value())) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        }

        if (refreshToken.getTokenStatus().value().equals(TokenStatus.REVOKED.value())) {
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_REVOKED);
        }

        Instant currentTime = Instant.now();
        if (currentTime.isAfter(refreshToken.getExpireTime()) ||
            currentTime.isAfter(refreshToken.getMaxLifeTime())
        ) {
            // Update refreshToken status to Expired here and in database
            expireRefreshToken(refreshToken);
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);
        }

        // Add more time to Expire Time ONLY. MaxLifeTime remains the same
        updateRefreshTokenExpireTime(refreshToken);

        if (refreshToken.getExpireTime().isAfter(refreshToken.getMaxLifeTime())) {
            // Update refreshToken status to Revoked here and in database
            revokeRefreshToken(refreshToken);

            // with this refreshToken, use that User to call buildRefreshToken and insert that to db
            RefreshToken newRefreshToken = jwtManager.buildRefreshToken(getUserFromRefreshToken(refreshToken));
            insertRefreshToken(newRefreshToken);
            return newRefreshToken;
        }

        return refreshToken;
    }

    public void updateRefreshTokenExpireTime(RefreshToken token)
    {
        token.setExpireTime(Instant.now().plus(serviceConfig.refreshTokenExpire()));
        // update data in db
        repo.updateRefreshTokenExpireTime(token.getId(), token.getExpireTime());
    }

    public void expireRefreshToken(RefreshToken token)
    {
        token.setTokenStatus(TokenStatus.EXPIRED);
        // update data in db
        repo.updateRefreshTokenStatusID(token.getId(), token.getTokenStatus().id());
    }

    public void revokeRefreshToken(RefreshToken token)
    {
        token.setTokenStatus(TokenStatus.REVOKED);
        // update data in db
        repo.updateRefreshTokenStatusID(token.getId(), token.getTokenStatus().id());
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        return repo.getUserByID(refreshToken.getUserId());
    }

    public void validateUserEmailAlreadyExist(String email) {
        repo.validateUserEmailAlreadyExist(email);
    }
}
