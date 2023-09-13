package com.springboot3.springsecurity.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class TestController {

    @GetMapping("/hello-world")
    public String helloWorld() {

        return "Hello World v1";
    }

}