package io.org.oreilly.methodsecurity;

import lombok.*;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import sun.rmi.runtime.Log;

import javax.annotation.security.RolesAllowed;
import javax.persistence.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@SpringBootApplication
@EnableJpaAuditing
@EnableGlobalMethodSecurity(prePostEnabled = true,
							jsr250Enabled = true,
							securedEnabled = true)
public class MethodSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(MethodSecurityApplication.class, args);
	}

	@Bean
	AuditorAware<String> auditor() {
		return new AuditorAware<String>() {
			@Override
			public Optional<String> getCurrentAuditor() {
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				if(null != authentication) {
					return Optional.ofNullable(authentication.getName());
				}
				return Optional.empty();
			}
		};
	}

	@Bean
	SecurityEvaluationContextExtension securityEvaluationContextExtension() {
		return new SecurityEvaluationContextExtension();
	}

}

@Configuration
@EnableWebSecurity
class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity security) throws Exception {

		// For H2 console view ::
		security.csrf().disable();
		//security.headers().xssProtection().disable();
		security.headers().frameOptions().disable();


		security.httpBasic();
		security.authorizeRequests().anyRequest().permitAll();

	}
}


class UserUserDetails implements UserDetails {

	private final User user;

	private final Set<GrantedAuthority> grantedAuthorities;

	public UserUserDetails(User user ) {
		this.user = user;
		this.grantedAuthorities = user.getAuthorities()
				.stream().map(au -> new SimpleGrantedAuthority("ROLE_"+au.getAuthority()))
				.collect(Collectors.toSet());
	}
	public User getUser() {
		return user;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.grantedAuthorities;
	}

	@Override
	public String getPassword() {
		return this.user.getPassword();
	}
	@Override
	public String getUsername() {
		return this.user.getEmail();
	}
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
	@Override
	public boolean isEnabled() {
		return true;
	}
}



@Service
@RequiredArgsConstructor
class UserRepositoryUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
		User user = this.userRepository.findByEmail(s);
		if(user != null) {
			return new UserUserDetails(user);
		}
		else throw new UsernameNotFoundException(String.format(" Couldn't find user %s " , s));
	}

}

@Transactional
@Component
@RequiredArgsConstructor
@Log4j2
class AppInitializer implements ApplicationRunner {

	private final MessageRepository messageRepository;
	private final UserRepository userRepository;
	private final AuthorityRepository authorityRepository;
	private final UserRepositoryUserDetailsService userRepositoryUserDetailsService;

	// Setting the current user Authentication to SecurityContextHolder::
	public void authenticate(String username) {
		UserDetails user = this.userRepositoryUserDetailsService.loadUserByUsername(username);
		Authentication authentication = new UsernamePasswordAuthenticationToken(user ,
				user.getPassword() , user.getAuthorities());
		//log.info("Setting " +authentication.toString()+ "to SecurityContextHolder ");
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	private void attemptAccess(String adminUser , String regularUser , Long msgId,
							   Function<Long, Message> messageFn) {
		authenticate(adminUser);
		log.info("Result for Rob Winch : " +messageFn.apply(msgId));

		try {
			authenticate(regularUser);
			log.info("Result for Bob : " +messageFn.apply(msgId));
		}
		catch (Throwable ex) {
			log.error("Oops no authority for Bob");
		}
	}

	@Override
	public void run(ApplicationArguments args) throws Exception {

		Authority user = this.authorityRepository.save(new Authority("USER")),
				admin = this.authorityRepository.save(new Authority("ADMIN"));

		User rob = this.userRepository.save(new User("rob", "password", admin, user));
		Message messageForRob = this.messageRepository.save(new Message(" Hi for Rob Winch !! " , rob));
		this.messageRepository.save(new Message("Hi 1 Rob", rob));
		this.messageRepository.save(new Message("Hi 2 Rob", rob));

		User bob = this.userRepository.save(new User("bob", "password", user));
		Message messageForBob = this.messageRepository.save(new Message("Hi for Bob" , bob));
		this.messageRepository.save(new Message("Hi 1 Bob", bob));

		log.info("rob : " +rob.toString());
		log.info("bob : " +bob.toString());

		/*attemptAccess(rob.getEmail() , bob.getEmail() , messageForRob.getId(),
				this.messageRepository::findByIdRolesAllowed);

		attemptAccess(rob.getEmail() , bob.getEmail() , messageForRob.getId(),
				this.messageRepository::findByIdSecured);

		attemptAccess(rob.getEmail() , bob.getEmail() , messageForRob.getId(),
				this.messageRepository::findByIdPreAuthorize);*/

		/*attemptAccess(rob.getEmail() , bob.getEmail() , messageForRob.getId(),
				this.messageRepository::findByIdBeanCheck);*/

		authenticate(rob.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0 , 5))
				.forEach(log::info);

		authenticate(bob.getEmail());
		this.messageRepository.findMessagesFor(PageRequest.of(0 , 5))
				.forEach(log::info);

		log.info("Audited message :: " +this.messageRepository.save(new Message("Hi Bob Audited ", bob)));



	}
}

@Service("authz")
@Log4j2
class PostAuthBean {

	public boolean check(Message message , User user) {
		log.info("Message : " +message.getText()+ " for user : " +user.getEmail());
		return message.getTo().getId().equals(user.getId());
	}
}

interface MessageRepository extends JpaRepository<Message, Long> {

	String QUERY = "select m from Message m where m.id = ?1";

	// JSR-250 ::
	@Query(QUERY)
	@RolesAllowed("ROLE_ADMIN")
	Message findByIdRolesAllowed (Long id);

	@Query(QUERY)
	@Secured({"ROLE_ADMIN", "ROLE_USER"})
	Message findByIdSecured (Long id);

	@Query(QUERY)
	@PreAuthorize("hasRole('ADMIN')")
	Message findByIdPreAuthorize(Long id);

	@Query(QUERY)
	@PostAuthorize("@authz.check(returnObject, principal?.user)")
	Message findByIdBeanCheck(Long id);

	@Query("select m from Message m where m.to.id = ?#{ principal?.user?.id }")
	Page<Message> findMessagesFor(Pageable pageable);
}

interface UserRepository extends JpaRepository<User, Long> {
	User findByEmail(String email);
}

interface AuthorityRepository extends JpaRepository<Authority , Long> {

}


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
class Message {
	@Id
	@GeneratedValue
	private Long id;

	private String text;
	@OneToOne
	private User to;

	@CreatedBy
	private String createdBy;

	@CreatedDate
	@Temporal( TemporalType.TIMESTAMP)
	private Date when;

	public Message(String text, User to) {
		this.text = text;
		this.to = to;
	}
}

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(exclude = "authorities")
class User {
	@Id
	@GeneratedValue
	private Long id;
	private String email , password;

	@ManyToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE})
	@JoinTable(name = "user_authority" , joinColumns = { @JoinColumn (name = "user_id")},
			inverseJoinColumns = { @JoinColumn (name = "authority_id")})
	private List<Authority> authorities = new ArrayList<>();

	public User(String email, String password, Set<Authority> authorities) {
		this.email = email;
		this.password = password;
		this.authorities.addAll(authorities);
	}

	public User(String email, String password) {
		this(email , password , new HashSet<>());
	}

	public User(String email, String password, Authority...authorities) {
		this(email , password , new HashSet<>(Arrays.asList(authorities)));
	}

}


@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString(exclude = "users")
class Authority {
	@Id
	@GeneratedValue
	private Long id;

	public Authority(String authority) {
		this.authority = authority;
	}

	public Authority(String authority, Set<User> users) {
		this.authority = authority;
		this.users.addAll(users);
	}

	private String authority;

	@ManyToMany(mappedBy = "authorities")
	private List<User> users = new ArrayList<>();

}
