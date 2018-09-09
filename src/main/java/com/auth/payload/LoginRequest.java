package com.auth.payload;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class LoginRequest {
    @NotBlank
    @Size(max = 140)
    private String userNameOrEmail;

    @NotNull
    @Size(min = 2, max = 6)
    private String password;

    public String getUserNameOrEmail() {
        return userNameOrEmail;
    }

    public void setUserNameOrEmail(String userNameOrEmail) {
        this.userNameOrEmail = userNameOrEmail;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}