package org.springframework.samples.petclinic.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final LoginAttemptService loginAttemptService;

	private final UserDetailsService userDetailsService;

	private final PasswordEncoder passwordEncoder;

	public CustomAuthenticationProvider(LoginAttemptService loginAttemptService, UserDetailsService userDetailsService,
			PasswordEncoder passwordEncoder) {
		this.loginAttemptService = loginAttemptService;
		this.userDetailsService = userDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String username = authentication.getName();

		// APP.3.1.A1–A3: Brute-Force-Schutz durch Account-Lockout
		if (loginAttemptService.isBlocked(username)) {
			throw new LockedException("Account gesperrt aufgrund zu vieler Fehlversuche");
		}

		// Nutzer und Passwort laden/prüfen
		UserDetails user = userDetailsService.loadUserByUsername(username);
		String rawPassword = authentication.getCredentials().toString();
		if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
			loginAttemptService.loginFailed(username);
			throw new BadCredentialsException("Ungültige Anmeldedaten");
		}

		// Erfolgreiche Anmeldung, Fehlversuche zurücksetzen
		loginAttemptService.loginSucceeded(username);

		return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
