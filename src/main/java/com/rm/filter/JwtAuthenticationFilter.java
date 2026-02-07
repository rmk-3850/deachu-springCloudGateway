package com.rm.filter;

import java.util.List;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rm.dto.ErrorCode;
import com.rm.dto.GResponse;
import com.rm.jwt.JwtTokenProcess;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config>{
	private final JwtTokenProcess process;
	private final ObjectMapper objectMapper;
	public JwtAuthenticationFilter(JwtTokenProcess process,ObjectMapper objectMapper) {
		super(Config.class);
		this.process=process;
		this.objectMapper=objectMapper;
	}
	public static class Config{}
	
	@Override
	public GatewayFilter apply(Config config) {
		return (exchange,chain)->{			
			ServerHttpRequest request=exchange.getRequest();
			
			String token=process.resolveToken(request);
			
			if(token==null) return onError(exchange, ErrorCode.NO_HEADER);
			
			if(!process.isValidToken(token)) return onError(exchange, ErrorCode.INVALID_TOKEN);
			Claims claims=process.getClaims(token);
			String uid=claims.getSubject();
			@SuppressWarnings("unchecked")
			List<String> list=claims.get("roles", List.class);
			String roles="";
			if(list!=null) {
				roles=String.join(",", list);
			}
			
			ServerHttpRequest modifiedRequest=exchange.getRequest().mutate()
					.header("X-User-Uid", uid)
					.header("X-User-Roles", roles)
					.build();
			return chain.filter(exchange.mutate().request(modifiedRequest).build());
		};
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
			return response.setComplete();
		}
	}
}
