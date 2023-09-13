package com.springboot3.springsecurity.Controller;

import org.apache.catalina.LifecycleState;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class TodoResource {

    public static final List<Todo> TODO_LIST = List.of(new Todo("AWS", "Cloud"),
            new Todo("Microservices", "Backend")
    );

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODO_LIST;
    }

}
record Todo(String usernmae, String description){}