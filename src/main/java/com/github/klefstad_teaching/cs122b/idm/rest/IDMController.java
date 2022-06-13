package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.model.request.AuthenticateRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.RefreshRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.RegisterRequest;
import com.github.klefstad_teaching.cs122b.idm.model.response.AuthenticateResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.LoginResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.RefreshResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponse;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;

    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate,
                         IDMServiceConfig config)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }

    /**
     * Register
     */
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @RequestBody RegisterRequest request
            )
    {
        String email = request.getEmail();
        char[] password = request.getPassword();

        // Check if User with this email already exists
        authManager.validateUserEmailAlreadyExist(email);

        // Check if Password does not meet length requirements
        // Check if Password does not meet character requirement
        validate.validatePassword(password);

        // Check if Email address has invalid format
        // Check if Email address has invalid length
        validate.validateEmail(email);

        authManager.createAndInsertUser(email, password);

        return new RegisterResponse()
                .setResult(IDMResults.USER_REGISTERED_SUCCESSFULLY)
                .toResponse();
    }

    /**
     * Login
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest request
    )
    {
        String email = request.getEmail();
        char[] password = request.getPassword();

        validate.validateEmail(email);
        validate.validatePassword(password);
        User authenticateUser = authManager.selectAndAuthenticateUser(email, password);

        // Both tokens expiration dates are determined by the values supplied in the application.yml file

        // Create accessToken
        String accessToken = jwtManager.buildAccessToken(authenticateUser);

        // Create refreshToken
        RefreshToken refreshToken = jwtManager.buildRefreshToken(authenticateUser);

        // Store refreshToken to database
        authManager.insertRefreshToken(refreshToken);

        return new LoginResponse()
                .setAccessToken(accessToken)
                .setRefreshToken(refreshToken.getToken())
                .setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY)
                .toResponse();
    }

    /**
     * Refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(
            @RequestBody RefreshRequest request
    )
    {
        // Check if the refreshToken is expired,
        // a new usable one is returned if not expired or not expired and beyond max lifetime
        RefreshToken newRefreshToken = authManager.verifyRefreshToken(request.getRefreshToken());

        User user = authManager.getUserFromRefreshToken(newRefreshToken);
        String accessToken = jwtManager.buildAccessToken(user);

        return new RefreshResponse()
                .setRefreshToken(newRefreshToken.getToken())
                .setAccessToken(accessToken)
                .setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN)
                .toResponse();
    }

    /**
     * Authenticate
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticateResponse> authenticate(
            @RequestBody AuthenticateRequest request
            )
    {
        jwtManager.verifyAccessToken(request.getAccessToken());

        return new AuthenticateResponse()
                .setResult(IDMResults.ACCESS_TOKEN_IS_VALID)
                .toResponse();
    }
}
