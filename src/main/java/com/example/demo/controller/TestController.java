package com.example.demo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/tenant/branch1/anonymous")
    public ResponseEntity<String> getAnonymous() {
        return ResponseEntity.ok("Hello Anonymous tenant 1");
    }

    @GetMapping("/tenant/branch2/anonymous")
    public ResponseEntity<String> get2Anonymous() {
        return ResponseEntity.ok("Hello Anonymous tenant 2");
    }


}