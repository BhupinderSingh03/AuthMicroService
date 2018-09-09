package com.auth.controller;

import com.auth.constants.AuthConstants;
import com.auth.exception.CustomException;
import com.auth.handler.RequestHandler;
import com.auth.model.Role;
import com.auth.model.RoleName;
import com.auth.model.User;
import com.auth.payload.*;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.security.CustomUserDetailsService;
import com.auth.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;
import java.net.URI;
import java.util.Collections;

/**
 * Auth Controller, An entry class for all incoming requests
 *
 * @author Bhupinder Singh
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtTokenProvider tokenProvider;

    @Autowired
    RequestHandler requestHandler;

    @Autowired
    CustomUserDetailsService customUserDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    /**
     * Validate the credentials and generate the jwt tokens
     *
     * @return access token and refresh token
     */
    @GetMapping("/signin")
    public ResponseEntity<?> tokenGenerator(@RequestHeader(AuthConstants.AUTH_KEY) String authCredentials) throws Exception {

        LoginRequest loginRequest = requestHandler.decodeCredentials(authCredentials);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUserNameOrEmail(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String refreshJwt = tokenProvider.generateRefreshToken(authentication);
        String accessJwt = tokenProvider.generateAccessToken(authentication);

        return ResponseEntity.ok(new JwtAuthenticationResponse(accessJwt, refreshJwt));
    }

    /**
     * Validate the refresh token and generate access token
     *
     * @return access token
     */
    @GetMapping("/refreshToken")
    public ResponseEntity<?> refreshToken(@RequestHeader(AuthConstants.AUTH_KEY) String authRefreshToken) throws Exception {
        try {
            if (StringUtils.hasText(authRefreshToken)) {

                String refreshJwt = requestHandler.getJwtFromStringRequest(authRefreshToken);
                String userName = tokenProvider.getUserNameFromJWT(refreshJwt);

                UserDetails userDetails = customUserDetailsService.loadUserByUsername(userName);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities());

                String accessJwtToken = tokenProvider.generateAccessToken(authentication);

                return ResponseEntity.ok(new RefreshJwtAuthenticationResponse(accessJwtToken));
            } else
                return ResponseEntity.ok(new ErrorResponse(AuthConstants.EMPTY_TOKEN));
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex.getMessage());
            return ResponseEntity.ok(new ErrorResponse(ex.getMessage()));
        }
    }

    /**
     * Validate the token
     *
     * @return status of token
     */
    @GetMapping("/validateToken")
    public ResponseEntity<?> validate(@RequestHeader(AuthConstants.AUTH_KEY) String authToken) throws Exception {
        return ResponseEntity.ok(new ApiResponse(true, "Token is valid"));
    }

    /**
     * Validate the access token and returns user details
     *
     * @return status of token
     */
    @GetMapping("/userDetails")
    public ResponseEntity<?> details(@RequestHeader(AuthConstants.AUTH_KEY) String authToken) throws Exception {
        String jwt = requestHandler.getJwtFromStringRequest(authToken);
        UserDetailsResponse response = tokenProvider.getUserNameAndRolesFromJWT(jwt);
        return ResponseEntity.ok(response);
    }


    /*
     * This is for user registration which will get removed after implementation of existing ldap details
     *
     * @return user registration status
     * */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, AuthConstants.USERNAME_EXIST),
                    HttpStatus.BAD_REQUEST);
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, AuthConstants.EMAIL_EXIST),
                    HttpStatus.BAD_REQUEST);
        }

        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword());

        user.setPassword(passwordEncoder.encode(user.getPassword()));

        RoleName role = null;
        if (signUpRequest.getUserRole().equals("admin")) {
            role = RoleName.ROLE_ADMIN;
        } else if (signUpRequest.getUserRole().equals("user")) {
            role = RoleName.ROLE_USER;
        }
        Role userRole = roleRepository.findByName(role)
                .orElseThrow(() -> new CustomException("User Role not set."));

        user.setRoles(Collections.singleton(userRole));

        User result = userRepository.save(user);

        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/users/{username}")
                .buildAndExpand(result.getUsername()).toUri();

        return ResponseEntity.created(location).body(new ApiResponse(true, "User registered successfully"));
    }
}
