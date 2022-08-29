package com.demo.jwt.controller;

import com.demo.jwt.common.Constants;
import com.demo.jwt.entity.User;
import com.demo.jwt.model.JwtRequest;
import com.demo.jwt.model.JwtResponse;
import com.demo.jwt.dto.UserDto;
import com.demo.jwt.service.JwtUserDetailsService;
import com.demo.jwt.util.JwtTokenUtil;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Expose a POST /authenticate api.
 * This api get username and password from request, and authenticate them using
 * Spring Authentication Manager. If credentials are valid, a token is generated
 * using the JwtTokenUtil and returns to the client.
 */
@RestController
@CrossOrigin
public class JwtTokenController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @PostMapping(Constants.URL_AUTHENTICATE)
    public JwtResponse createJwtToken(@RequestBody JwtRequest request) throws Exception {
        authenticate(request.getUsername(), request.getPassword());
        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        String token = jwtTokenUtil.generateToken(userDetails);
        return new JwtResponse(token, jwtTokenUtil.getJwtExpireInSeconds());
    }

    @PostMapping(Constants.URL_REGISTER)
    public User saveUser(@RequestBody UserDto user) throws Exception {
        return userDetailsService.save(user);
    }

    @GetMapping(Constants.URL_REFRESH_TOKEN)
    public JwtResponse refreshToken(HttpServletRequest request) throws Exception {
        // get the claims from the HttpRequest
        DefaultClaims claims = (io.jsonwebtoken.impl.DefaultClaims)request.getAttribute(Constants.ATTR_CLAIMS);
        Map<String, Object> expectedMap = getMapFromJwtClaims(claims);
        String token = jwtTokenUtil.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());
        return new JwtResponse(token, jwtTokenUtil.getJwtExpireInSeconds());
    }

    public Map<String, Object> getMapFromJwtClaims(DefaultClaims claims) {
        Map<String, Object> expectedMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            expectedMap.put(entry.getKey(), entry.getValue());
        }
        return expectedMap;
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }
}
