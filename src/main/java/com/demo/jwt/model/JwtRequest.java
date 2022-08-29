package com.demo.jwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * This class is used by the client to request for token
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtRequest implements Serializable {
    private String username;
    private String password;
}
