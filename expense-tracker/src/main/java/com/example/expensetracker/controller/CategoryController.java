package com.example.expensetracker.controller;

import com.example.expensetracker.model.Category;
import com.example.expensetracker.dto.CategoryDTO;
import com.example.expensetracker.model.User;
import com.example.expensetracker.repository.CategoryRepository;
import com.example.expensetracker.repository.UserRepository;
import com.example.expensetracker.exception.ResourceNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private UserRepository userRepository;

    @GetMapping
    public ResponseEntity<List<CategoryDTO>> list(@RequestParam Long userId) {
        List<Category> list = categoryRepository.findByUserId(userId);
        List<CategoryDTO> dto = list.stream().map(c -> new CategoryDTO(c.getId(), c.getName())).collect(Collectors.toList());
        return ResponseEntity.ok(dto);
    }

    @PostMapping
    public ResponseEntity<Category> create(@RequestBody Category c) {
        if (c.getUser() == null || c.getUser().getId() == null) {
            throw new ResourceNotFoundException("User id required");
        }
        Long uid = c.getUser().getId();
        User user = userRepository.findById(uid).orElseThrow(() -> new ResourceNotFoundException("User not found"));
        c.setUser(user);
        Category saved = categoryRepository.save(c);
        return ResponseEntity.ok(saved);
    }
}
