package com.example.expensetracker.service;

import com.example.expensetracker.dto.ExpenseDTO;
import com.example.expensetracker.exception.ResourceNotFoundException;
import com.example.expensetracker.model.Category;
import com.example.expensetracker.model.Expense;
import com.example.expensetracker.model.User;
import com.example.expensetracker.repository.CategoryRepository;
import com.example.expensetracker.repository.ExpenseRepository;
import com.example.expensetracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;

@Service
public class ExpenseService {
    @Autowired
    private ExpenseRepository expenseRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CategoryRepository categoryRepository;

    @Transactional
    public Expense createExpense(ExpenseDTO dto) {
        User user = userRepository.findById(dto.getUserId())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        Category category = categoryRepository.findById(dto.getCategoryId())
                .orElseThrow(() -> new ResourceNotFoundException("Category not found"));

        Expense e = new Expense(user, category, dto.getAmount(), dto.getDate(), dto.getDescription());
        return expenseRepository.save(e);
    }

    public Expense getExpense(Long id) {
        return expenseRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Expense not found"));
    }

    public org.springframework.data.domain.Page<com.example.expensetracker.dto.ExpenseDTO> listExpensesDto(Long userId, LocalDate start, LocalDate end, Pageable pageable) {
        return expenseRepository.findDtoByUserIdAndDateBetween(userId, start, end, pageable);
    }

    public org.springframework.data.domain.Page<com.example.expensetracker.dto.ExpenseDTO> listExpensesDtoByCategory(Long userId, Long categoryId, LocalDate start, LocalDate end, Pageable pageable) {
        return expenseRepository.findDtoByUserIdAndCategoryIdAndDateBetween(userId, categoryId, start, end, pageable);
    }

    public org.springframework.data.domain.Page<com.example.expensetracker.model.Expense> listExpenses(Long userId, LocalDate start, LocalDate end, Pageable pageable) {
        return expenseRepository.findAllByUserIdAndDateBetween(userId, start, end, pageable);
    }

    @Transactional
    public Expense updateExpense(Long id, ExpenseDTO dto) {
        Expense e = getExpense(id);
        if (dto.getAmount() != null) e.setAmount(dto.getAmount());
        if (dto.getDate() != null) e.setDate(dto.getDate());
        if (dto.getDescription() != null) e.setDescription(dto.getDescription());
        if (dto.getCategoryId() != null) {
            Category category = categoryRepository.findById(dto.getCategoryId())
                    .orElseThrow(() -> new ResourceNotFoundException("Category not found"));
            e.setCategory(category);
        }
        return expenseRepository.save(e);
    }

    @Transactional
    public void deleteExpense(Long id) {
        Expense e = getExpense(id);
        expenseRepository.delete(e);
    }
}
