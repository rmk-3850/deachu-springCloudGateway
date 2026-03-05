package com.rm.filter;

import java.util.List;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rm.exception.ErrorCode;
import com.rm.exception.GResponse;
import com.rm.jwt.JwtTokenProcess;

import io.jsonwebtoken.Claims;
import lombok.extern.log4j.Log4j2;
import reactor.core.publisher.Mono;
@Log4j2
@Component
public class JwtAuthenticationFilter implements WebFilter{
	private final JwtTokenProcess process;
	private final ObjectMapper objectMapper;
	public JwtAuthenticationFilter(JwtTokenProcess process,ObjectMapper objectMapper) {
		this.process=process;
		this.objectMapper=objectMapper;
	}
	
	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		
		ServerHttpRequest request=exchange.getRequest();
		
		String token=process.resolveToken(request);
		
		if(token==null) {
			return chain.filter(exchange);
		}
		
		if(!process.isValidToken(token)) return onError(exchange, ErrorCode.INVALID_TOKEN);
		
		Claims claims=process.getClaims(token);
		String uid=claims.getSubject();
		
		List<String> list=switch (claims.get("roles")){
			case null -> List.of();
			case List<?> rawList -> {
				if(rawList.stream().allMatch(String.class::isInstance)){
					yield rawList.stream().map(String.class::cast).toList();
				}
				yield null;
			}	
			default -> null;
		};
		
		if(list==null) return onError(exchange, ErrorCode.INVALID_TOKEN);

		String roles=(list.isEmpty()) ? "" : String.join(",", list);
		
        List<GrantedAuthority> authorities = list.stream()
			.<GrantedAuthority>map(SimpleGrantedAuthority::new)
			.toList();

        Authentication auth =
                new UsernamePasswordAuthenticationToken(uid, null, authorities);
		
		ServerHttpRequest modifiedRequest=exchange.getRequest().mutate()
				.headers(h->{
					h.remove("X-User-Uid");
					h.remove("X-User-Roles");
					h.add("X-User-Uid", uid);
					h.add("X-User-Roles", roles);
				})
				.build();
		return chain.filter(exchange.mutate().request(modifiedRequest).build())
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
	}
	
	private Mono<Void> onError(ServerWebExchange exchange,ErrorCode errorCode){ 
		ServerHttpResponse response=exchange.getResponse();
		GResponse gres=GResponse.fail(errorCode, exchange.getRequest().getPath().value());
		response.setStatusCode(gres.status());
		response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
		try {
			byte[] bytes=objectMapper.writeValueAsBytes(gres);
			DataBuffer buffer= response.bufferFactory().wrap(bytes);
			return response.writeWith(Mono.just(buffer));
		} catch (JsonProcessingException e) {
			log.error("onError fail", e);
			return response.setComplete();
		}
	}
}
