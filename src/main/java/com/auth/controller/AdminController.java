package com.auth.controller;

import com.auth.payload.UserRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private static final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String createPoll(@Valid @RequestBody UserRequest userRequest) {

       return "Congratulation Admin you can access this api";
    }
}
