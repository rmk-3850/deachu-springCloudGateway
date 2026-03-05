package com.rm;

import static org.mockito.BDDMockito.*;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.rm.config.TestSecurityConfig;
import com.rm.controller.TestController;
import com.rm.exception.ErrorCode;
import com.rm.filter.JwtAuthenticationFilter;
import com.rm.jwt.JwtTokenProcess;

import io.jsonwebtoken.Claims;

@WebFluxTest(controllers = TestController.class)
@Import({JwtAuthenticationFilter.class,TestSecurityConfig.class})
public class JwtAuthenticationFilterTest {
    @Autowired
    private WebTestClient client;
    @MockitoBean
    private JwtTokenProcess process;
    @Test
    void 인증_성공(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(true);
        Claims claims=mock(Claims.class);
        given(claims.getSubject()).willReturn("1");
        given(claims.get("roles")).willReturn(List.of("ROLE_USER"));
        given(process.getClaims("valid-token")).willReturn(claims);
        //when&then
        client.get()
            .uri("/api/test")
            .header("Authorization", "Bearer valid-token")
            .exchange()
            .expectStatus().isOk();
    }
    @Test
    void 토큰이_없으면_그대로_통과한다(){
        //given
        given(process.resolveToken(any())).willReturn(null);
        //when&then
        client.get()
            .uri("/api/test")
            .exchange()
            .expectStatus().isOk();
    }
    @Test
    void 토큰이_유효하지_않으면_에러를_반환한다(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(false);
        //when&then
        client.get()
            .uri("/api/test")
            .header("Authorization", "Bearer valid-token")
            .exchange()
            .expectStatus().isEqualTo(ErrorCode.INVALID_TOKEN.getStatus())
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody().jsonPath("$.code").isEqualTo(ErrorCode.INVALID_TOKEN.getCode());        
    }
    @Test
    void roles가_null이어도_인증객체는_생성된다(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(true);
        Claims claims=mock(Claims.class);
        given(claims.getSubject()).willReturn("1");
        given(claims.get("roles")).willReturn(null);
        given(process.getClaims("valid-token")).willReturn(claims);
        //when&then
        client.get()
            .uri("/api/test")
            .header("Authorization", "Bearer valid-token")
            .exchange()
            .expectStatus().isOk();
    }
    @Test
    void roles가_빈_리스트여도_인증객체는_생성된다(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(true);
        Claims claims=mock(Claims.class);
        given(claims.getSubject()).willReturn("1");
        given(claims.get("roles")).willReturn(List.of());
        given(process.getClaims("valid-token")).willReturn(claims);
        //when&then
        client.get()
            .uri("/api/test")
            .header("Authorization", "Bearer valid-token")
            .exchange()
            .expectStatus().isOk();
    }
    @Test
    void roles가_이상한타입이면_에러를_반환한다(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(true);
        Claims claims=mock(Claims.class);
        given(claims.getSubject()).willReturn("1");
        given(claims.get("roles")).willReturn(List.of(123, 456));
        given(process.getClaims("valid-token")).willReturn(claims);
        //when&then
        client.get()
            .uri("/api/test")
            .header("Authorization", "Bearer valid-token")
            .exchange()
            .expectStatus().isEqualTo(ErrorCode.INVALID_TOKEN.getStatus())
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody().jsonPath("$.code").isEqualTo(ErrorCode.INVALID_TOKEN.getCode());
    }
    @Test
    void 올바른_헤더를_심어준다(){
        //given
        given(process.resolveToken(any())).willReturn("valid-token");
        given(process.isValidToken("valid-token")).willReturn(true);
        Claims claims=mock(Claims.class);
        given(claims.getSubject()).willReturn("5");
        given(claims.get("roles")).willReturn(List.of());
        given(process.getClaims("valid-token")).willReturn(claims);
        //when&then
        client.get()
            .uri("/api/test")
            .headers(h->{
                h.add("Authorization", "Bearer valid-token");
                h.add("X-User-Uid", "1");
                h.add("X-User-Roles", "ADMIN");
            })
            .exchange()
            .expectHeader().valueEquals("X-User-Uid", "5")
            .expectHeader().valueEquals("X-User-Roles", "");
    }
}
