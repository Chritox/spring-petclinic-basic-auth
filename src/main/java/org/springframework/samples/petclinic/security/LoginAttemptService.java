package org.springframework.samples.petclinic.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptService {

	private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

	private final Cache<String, Integer> attempts = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).build();

	public void loginFailed(String user) {
		int count = attempts.asMap().merge(user, 1, Integer::sum);
	}

	public void loginSucceeded(String user) {
		attempts.invalidate(user);
	}

	public boolean isBlocked(String user) {
		Integer count = attempts.getIfPresent(user);
		return count != null && count >= 5;
	}

	public int getAttempts(String user) {
		Integer count = attempts.getIfPresent(user);
		return count != null ? count : 0;
	}

}
