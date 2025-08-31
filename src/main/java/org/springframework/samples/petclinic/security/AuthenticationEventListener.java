package org.springframework.samples.petclinic.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEventListener {

	private static final Logger log = LoggerFactory.getLogger(AuthenticationEventListener.class);

	private final LoginAttemptService loginAttemptService;

	public AuthenticationEventListener(LoginAttemptService loginAttemptService) {
		this.loginAttemptService = loginAttemptService;
	}

	@EventListener
	public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
		String username = (String) event.getAuthentication().getPrincipal();
		Object details = event.getAuthentication().getDetails();
		String ip = null;
		if (details instanceof WebAuthenticationDetails) {
			ip = ((WebAuthenticationDetails) details).getRemoteAddress();
		}
		loginAttemptService.loginFailed(username);
		int attempts = loginAttemptService.getAttempts(username);
		log.warn("Authentifizierungsversuch fehlgeschlagen für Benutzer '{}'; Fehlversuche: {}; IP: {}", username,
				attempts, ip);

		if (loginAttemptService.isBlocked(username)) {
			log.error("Benutzer '{}' gesperrt aufgrund zu vieler Fehlversuche (IP: {})", username, ip);
		}
	}

	@EventListener
	public void onAuthenticationLocked(AuthenticationFailureLockedEvent event) {
		String username = event.getAuthentication().getName();
		Object details = event.getAuthentication().getDetails();
		String ip = null;
		if (details instanceof WebAuthenticationDetails) {
			ip = ((WebAuthenticationDetails) details).getRemoteAddress();
		}
		log.error("Login-Versuch für gesperrten Benutzer '{}' (IP: {})", username, ip);
	}

	@EventListener
	public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
		String username = event.getAuthentication().getName();
		Object details = event.getAuthentication().getDetails();
		String ip = null;
		if (details instanceof WebAuthenticationDetails) {
			ip = ((WebAuthenticationDetails) details).getRemoteAddress();
		}
		loginAttemptService.loginSucceeded(username);
		log.info("Erfolgreiche Anmeldung für Benutzer '{}' (IP: {})", username, ip);
	}

}
