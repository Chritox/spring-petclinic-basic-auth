package org.springframework.samples.petclinic.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventListener {
	private static final Logger log = LoggerFactory.getLogger(SecurityEventListener.class);

	@EventListener
	public void onInvalidCsrfTokenException(InvalidCsrfTokenException event){
		event.ge
	}
}
