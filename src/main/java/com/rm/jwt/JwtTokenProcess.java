package com.rm.jwt;

import java.security.Key;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
@Log4j2
@Component
public class JwtTokenProcess {
	private final Key key;
	
	public JwtTokenProcess(@Value("${jwt.secret}") String base64Key) {
		byte[] keyBytes=Base64.getDecoder().decode(base64Key);
		this.key=Keys.hmacShaKeyFor(keyBytes);
	}
	
	public boolean isValidToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token);
			log.info("JWT verified: {}", token);
			return true;
		} catch (Exception e) {
			log.error("JWT verify failed", e);
			return false;
		}
	}
	
	public String resolveToken(ServerHttpRequest request) {
		HttpCookie cookie = request.getCookies().getFirst("accessToken");
		if (cookie != null) {
			return cookie.getValue();
		}
        return null;
    }
	
	public Claims getClaims(String token) {
		Claims claims = null;
		try {
			claims = Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();
			log.info("JWT verified: {}", claims.getSubject());
		} catch (Exception e) {
			log.error("JWT verify failed", e);
		}
		return claims;
	}
}
