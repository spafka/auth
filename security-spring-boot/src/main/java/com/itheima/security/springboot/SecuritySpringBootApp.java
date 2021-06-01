package com.itheima.security.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * @author Administrator
 * @version 1.0
 **/
@EnableWebSecurity(debug = true)
@SpringBootApplication
public class SecuritySpringBootApp {
    public static void main(String[] args) {
        SpringApplication.run(SecuritySpringBootApp.class,args);
    }
}
