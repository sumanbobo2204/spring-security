package com.org.security.login.oreillylogin;

import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.MessageDigestPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class OreillyLoginApplication {

	public static void main(String[] args) {
		SpringApplication.run(OreillyLoginApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	PasswordEncoder oldPasswordEncoder() {
		String md5 = "MD5";
		return new DelegatingPasswordEncoder(md5, Collections.singletonMap
				(md5, new MessageDigestPasswordEncoder(md5)));
	}

	@Bean
	CustomUserDetailsService customUserDetailsService() {
		Collection<UserDetails> users = Arrays.asList(
			new CustomUserDetails("jlong", oldPasswordEncoder().encode("jlong"), true, "USER"),
			new CustomUserDetails("rob", oldPasswordEncoder().encode("winch"), true, "USER","ADMIN"),
			new CustomUserDetails("bob", oldPasswordEncoder().encode("bob"), false, "ADMIN")
		);
		return new CustomUserDetailsService(users);
	}

	/*@Bean
	UserDetailsManager userDetailsManager() {
		return new InMemoryUserDetailsManager();
	}

	@Bean
	InitializingBean startup(UserDetailsManager userDetailsManager){
		return () -> {
			UserDetails bob = User.withUsername("bob").password("bob").roles("USER").build();
			userDetailsManager.createUser(bob);
		};
	}*/

}

/*@Controller
class LoginController {

	@GetMapping("/")
	String home(){
		return "/index";
	}

	@GetMapping("/login")
	String login(){
		return "/login";
	}

	@GetMapping("/logout-success")
	String logout(){
		return "/logout-success";
	}
}*/


/*@Configuration
@EnableWebSecurity
class LoginSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated();
		http.formLogin().loginPage("/login").permitAll();
		http.logout().logoutUrl("/logout").logoutSuccessUrl("/logout-success");
	}
}*/


@RestController
class GreetingsController {

	@GetMapping("/greetings")
	String greet(Principal principal) {
		return "Hello " +principal.getName();
	}
}

@Log4j2
class CustomUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

	// in real scenario it should be a database or any data provider::
	private final Map<String, UserDetails> userMap = new ConcurrentHashMap<>();

	public CustomUserDetailsService(Collection<UserDetails> userDetailsCollection) {
		userDetailsCollection.forEach(u -> this.userMap.put(u.getUsername(), u));
		userMap.forEach((k,v) -> log.info(v.getPassword() + " for :: " +v.getUsername()));
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// in real scenario any database query should happen ::
		if(this.userMap.containsKey(username)) {
			return this.userMap.get(username);
		}
		throw new UsernameNotFoundException(String.format("couldn't find %s!", username));
	}
	/**
	 * @param user
	 * @param newPassword
	 * @return
	 */
	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		log.info("prompted to update the password for user " + user.getUsername() +" to " +newPassword);
		this.userMap.put(user.getUsername() , new CustomUserDetails(
				user.getUsername(),
				newPassword,
				user.isEnabled(),
				user.getAuthorities().stream().map(
						o -> ((GrantedAuthority) o).getAuthority()).collect(Collectors.toList()).toArray(new String[0])
		));
		return loadUserByUsername(user.getUsername());
	}
}



class CustomUserDetails implements UserDetails {

	private final Set<GrantedAuthority> authorities;
	private final String userName, password;
	private final boolean isActive;

	public CustomUserDetails(String userName, String password, boolean isActive, String...authorities) {
		this.userName = userName;
		this.password = password;
		this.isActive = isActive;
		this.authorities = Stream.of(authorities)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public String getPassword() {
		return this.password;
	}

	@Override
	public String getUsername() {
		return this.userName;
	}

	@Override
	public boolean isAccountNonExpired() {
		return this.isActive;
	}

	@Override
	public boolean isAccountNonLocked() {
		return this.isActive;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.isActive;
	}

	@Override
	public boolean isEnabled() {
		return this.isActive;
	}
}


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Order(2)
class CustomAuthenticationProviderSecurityConfig extends WebSecurityConfigurerAdapter {

	//private final CustomAuthencicationProvider customAuthencicationProvider;

/*@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(customAuthencicationProvider);
	}*/


	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.authorizeRequests().anyRequest().authenticated();
	}
}


// Custom authentication provider class ::
@Component
class CustomAuthencicationProvider implements AuthenticationProvider {

	private boolean isvalidUser(String user, String pass) {
		// in real scenario call some other service for validation ::
		return user.equals("eric") && pass.equals("password");
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String user = authentication.getName();
		String password = authentication.getCredentials().toString();
		if(isvalidUser(user, password)) {
			return new UsernamePasswordAuthenticationToken(user, password, Collections.singletonList(
					new SimpleGrantedAuthority("USER")
			));
		}
		throw new BadCredentialsException("Could not authenticate using :: " +user+ " " +password);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// only supports username and password authentication.
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}


@Component
@Log4j2
class SecurityAuditEventListener {

	@EventListener
	public void onAuditEvent(AuditApplicationEvent auditApplicationEvent ) {
		log.info(auditApplicationEvent.getAuditEvent().getPrincipal());
		log.info(auditApplicationEvent.getAuditEvent().getData());
		log.info(auditApplicationEvent.getAuditEvent().getTimestamp());
	}
}
