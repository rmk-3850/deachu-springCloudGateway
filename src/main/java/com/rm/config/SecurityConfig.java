package com.rm.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import com.rm.filter.JwtAuthenticationFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowedOrigins(Arrays.asList("https://deachu.site","http://localhost:5173"));
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
			.cors(Customizer.withDefaults())
			.csrf(csrf->csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()))
			.formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
			.authorizeExchange(e->e
				.pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
				.pathMatchers("/oauth2/**").permitAll()
				.pathMatchers("/login/oauth2/**").permitAll()
	            .pathMatchers("/api/user/public/**").permitAll()
	            .pathMatchers("/api/user/admin/**").hasRole("ADMIN")
				.pathMatchers("/api/piece/public/**").permitAll()
	            .pathMatchers("/api/piece/admin/**").hasRole("ADMIN")
	            .anyExchange().authenticated()
			)
			.exceptionHandling(e -> 
				e.authenticationEntryPoint((exchange, ex) -> {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					return exchange.getResponse().setComplete();
				})
			)
			.addFilterAfter(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
			.build();
	}
}
