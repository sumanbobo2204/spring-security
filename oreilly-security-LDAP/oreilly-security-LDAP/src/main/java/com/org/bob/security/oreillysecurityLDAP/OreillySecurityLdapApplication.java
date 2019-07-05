package com.org.bob.security.oreillysecurityLDAP;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
public class OreillySecurityLdapApplication {

	public static void main(String[] args) {
		SpringApplication.run(OreillySecurityLdapApplication.class, args);
	}
}

@RestController
class GreetingsController {

	@RequestMapping("/loggeduser/ldap")
	String greet(Principal principal) {
		return "Hello LDAP User :: " + principal.getName();
	}
}

@Configuration
@EnableWebSecurity
class LdapSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// @formatter:off
		auth
				.ldapAuthentication()
				.userDnPatterns("uid={0},ou=people")
				.groupSearchBase("ou=groups")
				.contextSource()
					.ldif("classpath:test-server.ldif")
					.root("dc=springframework,dc=org")
					.and()
				.passwordCompare()
					.passwordAttribute("userPassword")
					.passwordEncoder(new LdapShaPasswordEncoder());
		// @formatter:on
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.authorizeRequests().anyRequest().authenticated();
	}
}
