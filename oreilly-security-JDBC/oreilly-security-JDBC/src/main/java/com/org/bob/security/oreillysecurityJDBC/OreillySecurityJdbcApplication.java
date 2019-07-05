package com.org.bob.security.oreillysecurityJDBC;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.security.Principal;

@SpringBootApplication
public class OreillySecurityJdbcApplication {

	public static void main(String[] args) {
		SpringApplication.run(OreillySecurityJdbcApplication.class, args);
	}

	@Bean
	UserDetailsManager userDetailsManager(DataSource dataSource){
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
        jdbcUserDetailsManager.setDataSource(dataSource);
		return  jdbcUserDetailsManager;
	}

	@Bean
	InitializingBean initializer(UserDetailsManager userDetailsManager) {
		return () -> {
			UserDetails bob = User.withDefaultPasswordEncoder().username("josh")
					.password("long")
					.roles("USER")
					.build();
			UserDetails robwinch = User.withUserDetails(bob).username("rwinch").build();
			userDetailsManager.createUser(robwinch);
			userDetailsManager.createUser(bob);
		};
	}
}

@Configuration
@EnableWebSecurity
class SecurityJdbcConfig extends WebSecurityConfigurerAdapter {


	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.authorizeRequests().anyRequest().authenticated();
	}
}

@RestController
class GreetingController {

	@RequestMapping("/greet")
	String greetLoggedUser(Principal principal) {
		return "Hello " +" "+principal.getName()+ " !! ";
	}

}
