package org.ada.school.controller.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.ada.school.dto.LoginDto;
import org.ada.school.dto.TokenDto;
import org.ada.school.exception.InvalidCredentialsException;
import org.ada.school.model.User;
import org.ada.school.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Calendar;
import java.util.Date;

import static org.ada.school.utils.Constants.CLAIMS_ROLES_KEY;
import static org.ada.school.utils.Constants.TOKEN_DURATION_MINUTES;

/**
 * @author Iván Camilo Rincón Saavedra
 * @version 1.0 2/14/2022
 * @project user-api
 */

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Value("${app.secret}")
    String secret;

    private final UserService userService;

    public AuthController(@Autowired UserService userService) {
        this.userService = userService;
    }

    private String generateToken(User user, Date expirationDate) {
        return Jwts.builder()
                .setSubject(user.getId())
                .claim(CLAIMS_ROLES_KEY, user.getRoles())
                .setIssuedAt(new Date())
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }

    private TokenDto generateTokenDto(User user) {
        Calendar expirationDate = Calendar.getInstance();
        expirationDate.add(Calendar.MINUTE, TOKEN_DURATION_MINUTES);
        String token = generateToken(user, expirationDate.getTime());
        return new TokenDto(token, expirationDate.getTime());
    }

    @PostMapping
    public TokenDto login(@RequestBody LoginDto loginDto) {
        // Checking if the user is already created
        User user = userService.findByEmail(loginDto.getEmail());
        if (BCrypt.checkpw(loginDto.getPassword(), user.getPassword())) {
            return generateTokenDto(user);
        } else {
            throw new InvalidCredentialsException();
        }
    }
}
