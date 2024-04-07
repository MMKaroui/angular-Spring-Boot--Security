package org.sid.ebankingbackend.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Time;
import java.time.Duration;
import java.time.Instant;
import java.time.chrono.ChronoLocalDate;
import java.time.chrono.Chronology;
import java.util.Map;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/auth")
public class SecurityController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    JwtEncoder jwtEncoder;
    @GetMapping ("/profile")
    public Authentication authentication(Authentication authentication){
        return authentication;
    }

    @PostMapping("/login")
    public Map<String,String> login (String username, String password){
        Authentication authentication= authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(username,password)
          );
        Instant instant=Instant.now();
       String scope= authentication.getAuthorities().stream()
               .map(GrantedAuthority::getAuthority).collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet =JwtClaimsSet.builder()
                .issuedAt(instant)
                //.expiresAt(instant.plus(10, )
                .subject(username)
                .claim("scope",scope)
                .build();
        JwtEncoderParameters jwtEncoderParameters =
                JwtEncoderParameters.from(
                        JwsHeader.with(MacAlgorithm.HS512).build(),
                        jwtClaimsSet
                );
        String  jwt =jwtEncoder.encode(jwtEncoderParameters).getTokenValue();
        return Map.of("access-token", jwt);
    }
}
