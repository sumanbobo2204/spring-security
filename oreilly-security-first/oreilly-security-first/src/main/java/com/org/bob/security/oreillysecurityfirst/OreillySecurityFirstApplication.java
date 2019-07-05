package com.org.bob.security.oreillysecurityfirst;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
public class OreillySecurityFirstApplication {

	public static void main(String[] args) {

		SpringApplication.run(OreillySecurityFirstApplication.class, args);
	}

	@Bean
	UserDetailsService userDetailsService(){
		return  new InMemoryUserDetailsManager();
	}

	@Bean
	InitializingBean initializer(UserDetailsManager userDetailsManager) {
		return () -> {
			UserDetails bob = User.withDefaultPasswordEncoder().username("bob")
					.password("bob")
					.roles("USER")
					.build();

			UserDetails robwinch = User.withUserDetails(bob).username("rob").build();

			userDetailsManager.createUser(robwinch);
			userDetailsManager.createUser(bob);
		};
	}

}

@Configuration
@EnableWebSecurity
class SecurityInMemeoryConfig extends WebSecurityConfigurerAdapter {
	/*@Override
	public void configure(WebSecurity web) throws Exception {
		super.configure(web);
	}*/

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.httpBasic();

		http
				.authorizeRequests().anyRequest().authenticated();
	}
}

@RestController
class GreetingController {

	@RequestMapping("/greet")
	String greetLoggedUser(Principal principal) {
		return "Hello " +" "+principal.getName()+ " !! ";
	}


}
