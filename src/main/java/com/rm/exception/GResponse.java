package com.rm.exception;

import org.springframework.http.HttpStatus;

public record GResponse(
		HttpStatus status,
		String code,
		String msg,
		String path
	) {
	public static GResponse fail(ErrorCode errorCode,String path){
		return new GResponse(
			errorCode.getStatus(),
			errorCode.getCode(),
			errorCode.getMsg(),
			path
		);
	}
}
