package com.demo.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.Serializable;

/**
 * This class is used by the client to receive token.
 */
@Getter
@AllArgsConstructor
public class JwtResponse implements Serializable {
    private String jwtToken;
    private int expireInSeconds;
}
