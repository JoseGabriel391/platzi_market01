package com.platzimarket01.web.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTUtil {
    private  static final String KEY = "pl4tz1";

    public String generateToken(UserDetails userDetails){
        return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, KEY).compact();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        return userDetails.getUsername().equals(extractUserName(token)) && !isTokenExpire(token);
    }

    // extrae el nombre del usuario del token
    public String extractUserName(String token){
        //en getSubject se encuentra el usuario de la peticion
        return getClaims(token).getSubject();
    }

    //Verifico si la fecha de vencimiento del token ya expiro o no
    public boolean isTokenExpire(String token){
        /* el metodo before() pregunta si esta antes de la fecha actual devuelve true el token ya expiro,
           si es posterior a la fecha actual devuelve false por lo tanto el token no expiro */
        return getClaims(token).getExpiration().before(new Date());
    }

    //Añado la llave(KEY) de la firma, verifica que la firma sea correcta
    private Claims getClaims(String token){
        return Jwts.parser().setSigningKey(KEY).parseClaimsJws(token).getBody();
    }
}
