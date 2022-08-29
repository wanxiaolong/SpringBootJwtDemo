package com.demo.jwt.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @RequestMapping("/hello/{name}")
    public String hello(@PathVariable("name") String name) {
        return "Hello " + name + "!";
    }
}
