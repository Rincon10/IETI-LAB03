package org.ada.school.dto;

import java.util.Date;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/13/2022
 * @project user-api
 */
public class TokenDto
{

    private String token;

    private Date expirationDate;

    public TokenDto( String token, Date expirationDate )
    {
        this.token = token;
        this.expirationDate = expirationDate;
    }

    public String getToken()
    {
        return token;
    }

    public Date getExpirationDate()
    {
        return expirationDate;
    }
}