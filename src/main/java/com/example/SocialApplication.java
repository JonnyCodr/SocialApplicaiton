package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.*;

@SpringBootApplication
@EnableOAuth2Sso
public class SocialApplication {

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}
}
