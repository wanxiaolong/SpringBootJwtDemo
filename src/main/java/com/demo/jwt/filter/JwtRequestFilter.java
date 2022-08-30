package com.demo.jwt.filter;

import com.demo.jwt.common.Constants;
import com.demo.jwt.service.JwtUserDetailsService;
import com.demo.jwt.util.JwtTokenUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.impl.Base64Codec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This class extends the Spring's web filter OncePerRequestFilter class,
 * For any incoming request, this filter class gets executed.
 * It checks if the request has a vlaid JWT token. If yes, then it sets the
 * Authentication in the context, to specify that tht current user is authenticated.
 */
@Component
@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final String BEARER_TOKEN_PREFIX = "Bearer ";
    private static final String BASIC_TOKEN_PREFIX = "Basic ";

    @Autowired
    private JwtUserDetailsService userDetailService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        final String tokenHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String username = null;
        String password = null;
        String jwtToken = null;

        if (tokenHeader != null) {
            // JWT token is in the format "Bearer [token]" format, thus need to remove the prefix.
            if (tokenHeader.startsWith(BEARER_TOKEN_PREFIX)) {
                jwtToken = tokenHeader.substring(BEARER_TOKEN_PREFIX.length());
                try {
                    username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                } catch (IllegalArgumentException e) {
                    logger.info("Unable to get username from token");
                } catch (ExpiredJwtException e) {
                    logger.info("JwtToken has expired");
                    String isRefreshToken = request.getHeader("isRefreshToken");
                    String requestURL = request.getRequestURL().toString();
                    // allow for Refresh Token creation if following conditions are true.
                    if (isRefreshToken != null
                            && isRefreshToken.equals("true")
                            && requestURL.endsWith(Constants.URL_REFRESH_TOKEN)) {
                        logger.info("Refreshing token");
                        allowForRefreshToken(e, request);
                    } else {
                        request.setAttribute("exception", e);
                    }
                }
            // Need to remove the "Basic " prefix.
            } else if (tokenHeader.startsWith(BASIC_TOKEN_PREFIX)) {
                String basicToken = tokenHeader.substring(BASIC_TOKEN_PREFIX.length());
                String decoded[] = Base64Codec.BASE64.decodeToString(basicToken).split(":");
                username = decoded[0].trim();
                password = decoded[1].trim();
                allowForGetToken(username, password, request);
            } else {
                logger.warn("Token has not begin with the \"Bearer\" or \"Basic\" prefix for URI: " + request.getRequestURI());
            }
        } else {
            logger.warn("No Authorization header found");
        }

        // once we get the token, then begin to validate it
        // the Spring Security stores the validated user int the SecurityContextHolder
        // after authentication, thus we retrieve it to check if it is null.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (username != null && authentication == null) {
            // this means this user has not been authenticated.
            // thus we load this user for authentication.
            UserDetails userDetails = userDetailService.loadUserByUsername(username);
            // validate this token
            if (jwtToken != null && jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                // if token is valid, configure Spring Security to set authentication object.
                // note that the password filed is removed from the authentication object.
                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(
                                username, null, userDetails.getAuthorities());
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                // after setting the Authentication object in the context, we specify
                // that the current user is authenticated.
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        // invoke next Filter in filterChain
        filterChain.doFilter(request, response);
    }

    private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {
        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(null, null, null);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        // Set the claims so that in controller we will be using it to create new JWT
        request.setAttribute(Constants.ATTR_CLAIMS, ex.getClaims());
    }

    private void allowForGetToken(String username, String password, HttpServletRequest request) {
        UserDetails userDetails = userDetailService.loadUserByUsername(username);
        if (passwordEncoder.matches(password, userDetails.getPassword())) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(username, null, null);
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            request.setAttribute(Constants.ATTR_USERNAME, username);
        }
    }
}
