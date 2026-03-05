package com.rm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import com.rm.filter.JwtAuthenticationFilter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
	
	@Bean
	public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http,JwtAuthenticationFilter jwtAuthenticationFilter) {
		return http
			.csrf(csrf->csrf.disable())
			.formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
			.authorizeExchange(e->e
	            .pathMatchers("/api/user/public/**").permitAll()
	            .pathMatchers("/api/user/admin/**").hasRole("ADMIN")
				.pathMatchers("/api/piece/public/**").permitAll()
	            .pathMatchers("/api/piece/admin/**").hasRole("ADMIN")
	            .anyExchange().authenticated()
			)
			.addFilterAfter(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
			.build();
	}
}
