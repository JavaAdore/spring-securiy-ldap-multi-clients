package com.security.ldap.springsecurityldap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@SpringBootApplication
public class SpringSecurityLdapApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityLdapApplication.class, args);
    }

 
}