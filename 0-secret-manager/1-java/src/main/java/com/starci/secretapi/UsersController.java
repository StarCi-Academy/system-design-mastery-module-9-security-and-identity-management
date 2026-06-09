package com.starci.secretapi;

import jakarta.annotation.PostConstruct;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

// GET /users — seeds 2 rows once, then returns all users; proves the DB connection works.
@RestController
@RequestMapping("/users")
public class UsersController {

    private final UserRepository userRepository;

    public UsersController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void seed() {
        if (userRepository.count() == 0) {
            userRepository.save(new User("Admin StarCi"));
            userRepository.save(new User("Học viên VIP"));
        }
    }

    @GetMapping
    public Map<String, Object> findAll() {
        List<Map<String, Object>> data = userRepository.findAll().stream()
                .map(u -> Map.<String, Object>of("id", u.getId(), "name", u.getName()))
                .collect(Collectors.toList());
        return Map.of("status", "success", "data", data);
    }
}
