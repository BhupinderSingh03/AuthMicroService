package com.auth.handler;

import com.auth.constants.AuthConstants;
import com.auth.constants.ErrorCodes;
import com.auth.exception.AppException;
import com.auth.payload.LoginRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import sun.misc.BASE64Decoder;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * A handler class responsible to manipulate the request
 *
 * @author Bhupinder Singh
 */
@Component
public class RequestHandler {

    /**
     * Decoding user credentials
     *
     * @return LoginRequest with user name and password
     */
    public LoginRequest decodeCredentials(String authCredentials) {

        String decodedAuth = "";
        String[] authParts = authCredentials.split("\\s+");
        String authInfo = authParts[1];
        byte[] bytes = null;
        try {
            bytes = new BASE64Decoder().decodeBuffer(authInfo);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        decodedAuth = new String(bytes);
        String credentials[] = decodedAuth.split(":");
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUserNameOrEmail(credentials[0]);
        loginRequest.setPassword(credentials[1]);
        return loginRequest;
    }

    /**
     * Get jwt from request
     *
     * @return JWT
     */
    public String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AuthConstants.AUTH_KEY);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        } else if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Basic ")) {
            return "Basic";
        }
        throw new AppException("Jwt is empty or Basic/Bearer missing", ErrorCodes.UNNAUTHORIZED.toString());
    }

    /**
     * Get jwt from string request
     *
     * @return JWT
     */
    public String getJwtFromStringRequest(String request) {
        if (StringUtils.hasText(request) && request.startsWith("Bearer ")) {
            return request.substring(7, request.length());
        }
        throw new AppException("Jwt is empty or Bearer missing", ErrorCodes.UNNAUTHORIZED.toString());
    }
}
