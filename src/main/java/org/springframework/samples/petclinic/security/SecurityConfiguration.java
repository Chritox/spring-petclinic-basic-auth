package org.springframework.samples.petclinic.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Bean
	public LoginAttemptService loginAttemptService() {
		return new LoginAttemptService();
	}

	@Bean
	public AuthenticationProvider customAuthenticationProvider(LoginAttemptService loginAttemptService,
			UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {

		return new CustomAuthenticationProvider(loginAttemptService, userDetailsService, passwordEncoder);
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			// APP.3.1.A1: Authentisierung – Clients müssen sich für geschützte Ressourcen
			// authentifizieren
			.authorizeHttpRequests(auth -> auth.requestMatchers("/oups", "/oups.*", "/oups/**")
				.permitAll()
				.requestMatchers("/resources/css/**", "/webjars/**", "/resources/images/**", "/resources/fonts/**")
				.permitAll()
				.requestMatchers("/error", "/error.*", "/error/**")
				.permitAll()
				.requestMatchers("/", "/vets*", "/vets/**")
				.permitAll()
				.requestMatchers("/pets/**", "/owners/**")
				.hasRole("VET")
				.anyRequest()
				.authenticated())
			// APP.3.1.A1: Angemessene Authentisierungsmethode – Formular-Login statt
			// Basic Auth
			.formLogin((form) -> form.loginPage("/login").permitAll())
			// APP.3.1.A1: Grenzwerte für fehlgeschlagene Anmeldeversuche (durch Framework
			// gehandhabt)
			.logout(LogoutConfigurer::permitAll)

			// APP.3.2.A5: Authentisierung – kryptografisch gesicherte Passwörter (siehe
			// passwordEncoder)
			// APP.3.1.A7: Schutz vor automatisierter Nutzung – CSRF verhindert
			// automatisierte Angriffe
			.csrf(Customizer.withDefaults())

			// APP.3.1.A12: Sichere Konfiguration – Session-Management
			.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

			// APP.3.1.A21: Sichere HTTP-Konfiguration – Sicherheitsrelevante
			// HTTP-Response-Header
			// APP.3.2.A11: TLS-Verschlüsselung enforcing via HSTS
			.headers((headers) -> headers
				// APP.3.1.A21: Strict-Transport-Security Header
				.httpStrictTransportSecurity((hsts) -> hsts.maxAgeInSeconds(31536000) // 1
																						// Jahr
					.includeSubDomains(true))
				// APP.3.1.A21: Content-Security-Policy gegen XSS
				.contentSecurityPolicy((csp) -> csp.policyDirectives("default-src 'self'"))
				// APP.3.1.A21: X-Content-Type-Options Header
				.contentTypeOptions(Customizer.withDefaults())
				// APP.3.1.A21: XSS-Protection
				.xssProtection(Customizer.withDefaults())
				// APP.3.1.A21: Clickjacking-Schutz
				.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
			// APP.3.1.A21: Cache-Control wird durch Spring Security automatisch gesetzt
			);

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		// APP.3.1.A14: Schutz vertraulicher Daten – Salted Hash-Verfahren für
		// Zugangsdaten
		// APP.3.2.A5: Authentisierung – kryptografisch gesicherte Passwörter
		UserDetails user = User.builder()
			.username("user")
			.password(passwordEncoder().encode("password"))
			.roles("USER")
			.build();

		UserDetails vet = User.builder()
			.username("vet")
			.password(passwordEncoder().encode("vetpass"))
			.roles("VET")
			.build();

		return new InMemoryUserDetailsManager(user, vet);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// APP.3.1.A14: Sichere kryptografische Algorithmen – BCrypt mit Salting
		// APP.3.2.A5: Kryptografisch gesicherte Passwörter
		return new BCryptPasswordEncoder(12); // Work-Factor 12 für erhöhte Sicherheit
	}

}
