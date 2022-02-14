package org.ada.school.exception;

import org.ada.school.dto.server.ServerErrorResponseDto;
import org.ada.school.model.enumData.ErrorCodeEnum;
import org.springframework.http.HttpStatus;

import javax.ws.rs.InternalServerErrorException;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/14/2022
 * @project user-api
 */
public class InvalidCredentialsException extends InternalServerErrorException {
    private ServerErrorResponseDto serverErrorResponseDto;

    public InvalidCredentialsException() {
        super();
        serverErrorResponseDto = new ServerErrorResponseDto("User not found",
                ErrorCodeEnum.USER_NOT_FOUND,
                HttpStatus.NOT_FOUND);
    }

    public InvalidCredentialsException(ServerErrorResponseDto serverErrorResponseDto) {
        super();
        this.serverErrorResponseDto = serverErrorResponseDto;
    }
}
