package org.ada.school.dto.server;

import org.ada.school.model.enumData.ErrorCodeEnum;
import org.springframework.http.HttpStatus;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/14/2022
 * @project user-api
 * Structure server error responses
 */
public class ServerErrorResponseDto {
    String message;
    ErrorCodeEnum errorCode;
    int httpStatus;

    public ServerErrorResponseDto(String message, ErrorCodeEnum errorCode, HttpStatus httpStatus) {
        this.message = message;
        this.errorCode = errorCode;
        this.httpStatus = httpStatus.value();
    }

    public String getMessage() {
        return message;
    }

    public ErrorCodeEnum getErrorCode() {
        return errorCode;
    }

    public int getHttpStatus() {
        return httpStatus;
    }
}
