package org.springframework.samples.petclinic.security;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

class CsrfFailureEvent {

	private final HttpServletRequest request;

	private final Exception exception;

	public CsrfFailureEvent(HttpServletRequest request, Exception exception) {
		this.request = request;
		this.exception = exception;
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public Exception getException() {
		return exception;
	}

}

class HttpSecurityHeaderViolationEvent {

	private final HttpServletRequest request;

	private final String violationType;

	private final String violationDetails;

	private final String blockedUri;

	public HttpSecurityHeaderViolationEvent(HttpServletRequest request, String violationType, String violationDetails,
			String blockedUri) {
		this.request = request;
		this.violationType = violationType;
		this.violationDetails = violationDetails;
		this.blockedUri = blockedUri;
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public String getViolationType() {
		return violationType;
	}

	public String getViolationDetails() {
		return violationDetails;
	}

	public String getBlockedUri() {
		return blockedUri;
	}

}

@Component
public class SecurityEventListener {

	private static final Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

	// APP.3.1.A7: Protokollierung von CSRF-Schutz vor automatisierter Nutzung
	// APP.3.2.A4: Protokollierung von Server-Fehlern und sicherheitsrelevanten
	// Ereignissen
	@EventListener
	public void onCsrfFailureEvent(CsrfFailureEvent event) {
		String site = event.getRequest().getRequestURL().toString();
		String ip = event.getRequest().getRemoteAddr();
		String userAgent = event.getRequest().getHeader("User-Agent");

		log.warn("CSRF-Fehler erkannt: URL='{}', IP='{}', User-Agent='{}', Fehler: {} ", site, ip, userAgent,
				event.getException().getMessage());
	}

	// APP.3.2.A4: Protokollierung fehlgeschlagener Zugriffe aufgrund mangelnder
	// Berechtigung
	@EventListener
	public void onAuthorizationDenied(AuthorizationDeniedEvent<?> event) {
		String username = event.getAuthentication().get().getName();
		String resource = event.getObject().toString();

		log.warn("Autorisierung verweigert für Benutzer '{}' beim Zugriff auf Ressource: {} ", username, resource);
	}

	// Session-Management gemäß APP.3.1.A12: Sichere Konfiguration - Session-Management
	@EventListener
	public void onSessionCreated(HttpSessionCreatedEvent event) {
		String sessionId = event.getSession().getId();
		int maxInactive = event.getSession().getMaxInactiveInterval();

		log.info("Neue Session erstellt: ID='{}', Max-Inaktiv-Zeit={}s ", sessionId, maxInactive);
	}

	// Session-Management gemäß APP.3.1.A12: Sichere Konfiguration - Session-Management
	@EventListener
	public void onSessionDestroyed(HttpSessionDestroyedEvent event) {
		String sessionId = event.getId();

		log.info("Session zerstört: ID='{}' ", sessionId);
	}

	// APP.3.2.A4: Protokollierung erfolgreicher Zugriffe (Logout als erfolgreiche
	// Beendigung)
	@EventListener
	public void onLogoutSuccess(LogoutSuccessEvent event) {
		String username = event.getAuthentication().getName();
		log.info("Erfolgreiche Abmeldung für Benutzer '{}' ", username);
	}

}
