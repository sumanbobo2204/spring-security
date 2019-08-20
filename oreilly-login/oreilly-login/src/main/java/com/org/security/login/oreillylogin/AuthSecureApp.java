package com.org.security.login.oreillylogin;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SpringBootApplication
public class AuthSecureApp {

    public static void main(String[] args) {
        SpringApplication.run(AuthSecureApp.class, args);
    }

    @Bean
    PasswordEncoder newPasswordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CustomizedUserDetailsService customizedUserDetailsService() {
        Collection<UserDetails> users = Arrays.asList(
        new CustomizedUser("kane" , newPasswordEncoder().encode("kane"), true, "ADMIN"),
        new CustomizedUser("rock" , newPasswordEncoder().encode("rock"), true, "USER")
        );
        return new CustomizedUserDetailsService(users);
    }

    @Bean
    Foo foo(){return new Foo();}
}

class Foo {
    public static final String TEST = "TEST";
}


@Configuration
@EnableWebSecurity
@Order(3)
class ActuatorSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
            http
                .requestMatcher(EndpointRequest.toAnyEndpoint())
                    .authorizeRequests()
                        .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll()
                        .anyRequest().authenticated()
                .and()
                .httpBasic();

    }
}

@Configuration
@EnableWebSecurity
@Order(1)
class AuthorizationConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity security) throws Exception {

            security.csrf().disable();
            //security.headers().xssProtection().disable();
            //security.headers().frameOptions().disable();
            security.headers().contentSecurityPolicy("default-src 'self'");
            security.httpBasic();

            security
                .authorizeRequests()
                .mvcMatchers("/root").hasAnyAuthority("ADMIN")
                .mvcMatchers(HttpMethod.GET,"/a").access("hasAnyAuthority('USER')")
                .mvcMatchers("/users/{name}").access("#name == principal?.username")
                .mvcMatchers(HttpMethod.POST, "/b").access("@authz.check( request, principal )")
                .anyRequest().permitAll();
    }
}

@Service("authz")
@Log4j2
class AuthService {

    public boolean check(HttpServletRequest request, CustomizedUser principal) {
        log.info("checking request : " +request.getRequestURI() +" for user : " +principal.getUsername());
        return true;
    }
}


@RestController
class RootRestController {
    @GetMapping("/root")
    String root() {
        return "root";
    }
}

@RestController
class LettersRestController {
    @GetMapping("/a")
    String a(){return "a";}

    @PostMapping("/b")
    String b(){return "b";}

    @GetMapping("/c")
    String c(){return "c";}
}

@RestController
class UserRestController {
    @GetMapping("/users/{name}")
    String getUserName(@PathVariable String name){
        return "User : " +name;
    }
}


@Log4j2
class CustomizedUserDetailsService implements UserDetailsService {

    private Map<String, UserDetails> userDetailsMap = new ConcurrentHashMap<>();

    @Autowired
    private Foo foooo;

    CustomizedUserDetailsService(Collection<UserDetails> userDetails){
        userDetails.forEach(u -> this.userDetailsMap.put(u.getUsername(), u));
        this.userDetailsMap.forEach((k, v) -> log.info(" User : " +k+ " Password : " +v.getPassword() ));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (!this.userDetailsMap.containsKey(username)) {
            throw new UsernameNotFoundException("No user found with name: " +username );
        }
        return this.userDetailsMap.get(username);
    }
}



class CustomizedUser implements UserDetails {

    private Set<GrantedAuthority> grantedAuthorities;
    private final String userName, password;
    private final boolean isActive;

    public CustomizedUser(String userName, String password, boolean isActive, String...authorities) {
        this.userName = userName;
        this.password = password;
        this.isActive = isActive;
        this.grantedAuthorities = Stream.of(authorities)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.grantedAuthorities;
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