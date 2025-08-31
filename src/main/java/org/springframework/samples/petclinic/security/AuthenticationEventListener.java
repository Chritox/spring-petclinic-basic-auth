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

	// APP.3.1.A1: Protokollierung fehlgeschlagener Authentisierungsversuche
	@EventListener
	public void onAuthenticationBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
		String username = event.getAuthentication().getName();
		String ip = extractIp(event.getAuthentication().getDetails());
		loginAttemptService.loginFailed(username);
		int attempts = loginAttemptService.getAttempts(username);

		log.warn(
				"Authentifizierungsversuch fehlgeschlagen für Benutzer '{}'; Fehlversuche: {}; IP: {} "
						+ "[BSI APP.3.1.A1/APP.3.2.A4: Sicherheitsrelevantes Ereignis protokolliert]",
				username, attempts, ip);

		// APP.3.1.A1: Grenzwerte für fehlgeschlagene Anmeldeversuche
		if (loginAttemptService.isBlocked(username)) {
			log.error("Benutzer '{}' gesperrt aufgrund zu vieler Fehlversuche (IP: {}) "
					+ "[BSI APP.3.1.A1: Grenzwert für fehlgeschlagene Anmeldeversuche erreicht]", username, ip);
		}
	}

	// APP.3.1.A1: Protokollierung von Anmeldeversuchen mit gesperrten Konten
	@EventListener
	public void onAuthenticationLocked(AuthenticationFailureLockedEvent event) {
		String username = event.getAuthentication().getName();
		String ip = extractIp(event.getAuthentication().getDetails());

		// APP.3.2.A4: Protokollierung fehlgeschlagener Zugriffe aufgrund mangelnder
		// Berechtigung
		log.error(
				"Login-Versuch für gesperrten Benutzer '{}' (IP: {}) "
						+ "[BSI APP.3.1.A1/APP.3.2.A4: Zugriff auf geschützte Ressource mit gesperrtem Konto]",
				username, ip);
	}

	// APP.3.2.A4: Protokollierung erfolgreicher Zugriffe auf Ressourcen
	@EventListener
	public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
		String username = event.getAuthentication().getName();
		String ip = extractIp(event.getAuthentication().getDetails());
		loginAttemptService.loginSucceeded(username);

		log.info(
				"Erfolgreiche Anmeldung für Benutzer '{}' (IP: {}) "
						+ "[BSI APP.3.2.A4: Erfolgreicher Zugriff auf geschützte Ressource protokolliert]",
				username, ip);
	}

	private String extractIp(Object details) {
		if (details instanceof WebAuthenticationDetails detailsObj) {
			return detailsObj.getRemoteAddress();
		}
		return "UNKNOWN";
	}

}
