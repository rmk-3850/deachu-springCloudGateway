package com.rm.exception;

import org.springframework.http.HttpStatus;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode {
	INVALID_TOKEN(HttpStatus.UNAUTHORIZED,"AUTH-001","유효하지 않은 토큰입니다.");
	private final HttpStatus status;
	private final String code;
	private final String msg;
}
