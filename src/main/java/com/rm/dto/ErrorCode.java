package com.rm.dto;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
	NO_HEADER(HttpStatus.UNAUTHORIZED,"AUTH-001","잘못된 헤더입니다."),
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED,"AUTH-002","유효하지 않은 토큰입니다.");
	private final HttpStatus status;
	private final String code;
	private final String msg;
}
