package com.auth;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.auth.model.Role;
import com.auth.model.RoleName;
import com.auth.model.User;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;import io.jsonwebtoken.lang.Collections;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthApplication {

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }
    
    @Bean
    public ApplicationRunner init(UserRepository userRepo, PasswordEncoder passwordEncoder, RoleRepository roleRepo) {
    	return args -> {
    		User user = userRepo.findByUsernameOrEmail("ajayuser", "ajayuser@gmail.com").orElse(null);
    		if(user == null) {
    			user = new User();
    			Role admin = roleRepo.findByName(RoleName.ROLE_USER).orElse(new Role(RoleName.ROLE_USER));
        		user.setEmail("ajayuser@gmail.com");
        		user.setName("ajay");
        		user.setUsername("ajayuser");
        		user.setPassword(passwordEncoder.encode("password"));
        		user.setRoles(java.util.Collections.singleton(admin));
        		
        		userRepo.save(user);
    		}
    		
    	};
    }
}
