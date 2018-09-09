package com.auth.payload;

public class UserDetailsResponse {

    private String userName;
    private String roles;

    public UserDetailsResponse(String userName,String roles) {
        this.userName = userName;
        this.roles =  roles;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }
}
