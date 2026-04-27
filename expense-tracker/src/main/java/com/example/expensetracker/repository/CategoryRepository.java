package com.example.expensetracker.repository;

import com.example.expensetracker.model.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface CategoryRepository extends JpaRepository<Category, Long> {
    @Query("SELECT DISTINCT c FROM Category c WHERE c.user.id = :userId ORDER BY c.name")
    List<Category> findByUserId(@Param("userId") Long userId);
}
