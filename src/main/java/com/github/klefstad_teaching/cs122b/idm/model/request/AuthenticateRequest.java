package com.github.klefstad_teaching.cs122b.idm.model.request;

public class AuthenticateRequest {
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public AuthenticateRequest setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }
}
