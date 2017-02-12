package com.example;

import java.security.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.*;
import org.springframework.security.config.annotation.web.builders.*;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.oauth2.config.annotation.web.configuration.*;
import org.springframework.security.web.csrf.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@RequestMapping("/user")
	public Principal user(Principal principal) {
		return principal;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/", "/login**", "/webjars/**")
				.permitAll()
				.anyRequest()
				.authenticated()
				.and().logout().logoutSuccessUrl("/").permitAll()
				.and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}
}
