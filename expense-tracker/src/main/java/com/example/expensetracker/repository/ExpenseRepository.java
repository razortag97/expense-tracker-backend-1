package com.example.expensetracker.repository;

import com.example.expensetracker.dto.ExpenseDTO;
import com.example.expensetracker.model.Expense;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;

public interface ExpenseRepository extends JpaRepository<Expense, Long> {
    Page<Expense> findAllByUserIdAndDateBetween(Long userId, LocalDate start, LocalDate end, Pageable pageable);

    @Query("SELECT new com.example.expensetracker.dto.ExpenseDTO(e.id, u.id, u.name, c.id, c.name, e.amount, e.date, e.description) " +
            "FROM Expense e JOIN e.user u JOIN e.category c " +
            "WHERE u.id = :userId AND e.date BETWEEN :start AND :end")
    Page<ExpenseDTO> findDtoByUserIdAndDateBetween(@Param("userId") Long userId, @Param("start") LocalDate start, @Param("end") LocalDate end, Pageable pageable);

    @Query("SELECT new com.example.expensetracker.dto.ExpenseDTO(e.id, u.id, u.name, c.id, c.name, e.amount, e.date, e.description) " +
            "FROM Expense e JOIN e.user u JOIN e.category c " +
            "WHERE u.id = :userId AND c.id = :categoryId AND e.date BETWEEN :start AND :end")
    Page<ExpenseDTO> findDtoByUserIdAndCategoryIdAndDateBetween(@Param("userId") Long userId, @Param("categoryId") Long categoryId, @Param("start") LocalDate start, @Param("end") LocalDate end, Pageable pageable);
}
