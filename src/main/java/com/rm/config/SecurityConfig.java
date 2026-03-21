package com.rm.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.rm.filter.JwtAuthenticationFilter;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOriginPatterns(Arrays.asList(
			"https://deachu.site",
			"https://*.deachu.site",
			"http://localhost:5173"));
		config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		config.setAllowedHeaders(Arrays.asList("*"));
		config.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", config);
		return source;
	}
	@Bean
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http,JwtAuthenticationFilter jwtAuthenticationFilter) {
		return http
			.cors(cors->cors.configurationSource(corsConfigurationSource()))
			.csrf(csrf->csrf
				.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
				.requireCsrfProtectionMatcher(exchange -> {
					String path = exchange.getRequest().getPath().value();
					HttpMethod method = exchange.getRequest().getMethod();
				
					// 1. GET, HEAD, OPTIONS 등의 안전한 메서드는 CSRF 검사 제외
					if (method == HttpMethod.GET ||method == HttpMethod.OPTIONS ||
						method == HttpMethod.HEAD || method == HttpMethod.TRACE) {
						return ServerWebExchangeMatcher.MatchResult.notMatch();
					}
				
					// 2. 화이트리스트(Public API) 경로도 CSRF 검사 제외 (로그인, 회원가입 등)
					if (path.startsWith("/api/user/public/") || 
						path.startsWith("/api/piece/public/") || 
						path.startsWith("/oauth2/") ||
						path.startsWith("/login/oauth2/")) {
						return ServerWebExchangeMatcher.MatchResult.notMatch();
					}
				
					// 3. 그 외의 모든 POST, PUT, DELETE 요청은 CSRF 토큰 검사 수행
					return ServerWebExchangeMatcher.MatchResult.match();
				})
			)
			.formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
			.authorizeExchange(e->e
				.pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
				.pathMatchers("/oauth2/**").permitAll()
				.pathMatchers("/login/oauth2/**").permitAll()
				.pathMatchers("/api/csrf").permitAll()
	            .pathMatchers("/api/user/public/**").permitAll()
	            .pathMatchers("/api/user/admin/**").hasRole("ADMIN")
				.pathMatchers("/api/piece/public/**").permitAll()
	            .pathMatchers("/api/piece/admin/**").hasRole("ADMIN")
	            .anyExchange().authenticated()
			)
			.exceptionHandling(e -> 
				e.authenticationEntryPoint((exchange, ex) -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					log.error(ex.getMessage());
					return exchange.getResponse().setComplete();
				})
			)
			.addFilterBefore((exchange, chain) -> {
				Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
				return (csrfToken != null ? csrfToken.then() : Mono.empty())
						.then(chain.filter(exchange));
			}, SecurityWebFiltersOrder.CSRF)
			.addFilterAfter(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
			.build();
	}
}
