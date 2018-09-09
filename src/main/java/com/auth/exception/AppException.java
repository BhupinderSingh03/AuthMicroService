package com.auth.exception;

public class AppException extends RuntimeException {

    private final String message;
    private final String httpStatus;

    public AppException(String message, String httpStatus) {
        this.message = message;
        this.httpStatus = httpStatus;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public String getHttpStatus() {
        return httpStatus;
    }
}
