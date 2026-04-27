package com.example.expensetracker.controller;

import com.example.expensetracker.dto.ExpenseDTO;
import com.example.expensetracker.model.Expense;
import com.example.expensetracker.service.ExpenseService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;

@RestController
@RequestMapping("/api/expenses")
public class ExpenseController {
    @Autowired
    private ExpenseService expenseService;
    @PostMapping
    public ResponseEntity<ExpenseDTO> create(@RequestBody ExpenseDTO dto) {
        Expense e = expenseService.createExpense(dto);
        return ResponseEntity.ok(toDto(e));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ExpenseDTO> get(@PathVariable Long id) {
        return ResponseEntity.ok(toDto(expenseService.getExpense(id)));
    }

    @GetMapping
    public ResponseEntity<Page<ExpenseDTO>> list(
            @RequestParam Long userId,
            @RequestParam(required = false) Long categoryId,
            @RequestParam(required = false) String start,
            @RequestParam(required = false) String end,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        LocalDate s = start == null ? LocalDate.now().minusYears(1) : LocalDate.parse(start);
        LocalDate e = end == null ? LocalDate.now() : LocalDate.parse(end);
        Page<ExpenseDTO> dtoPage;
        if (categoryId != null) {
            dtoPage = expenseService.listExpensesDtoByCategory(userId, categoryId, s, e, PageRequest.of(page, size));
        } else {
            dtoPage = expenseService.listExpensesDto(userId, s, e, PageRequest.of(page, size));
        }
        return ResponseEntity.ok(dtoPage);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ExpenseDTO> update(@PathVariable Long id, @RequestBody ExpenseDTO dto) {
        return ResponseEntity.ok(toDto(expenseService.updateExpense(id, dto)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        expenseService.deleteExpense(id);
        return ResponseEntity.noContent().build();
    }

    private ExpenseDTO toDto(Expense e) {
        if (e == null) return null;
        ExpenseDTO d = new ExpenseDTO();
        d.setId(e.getId());
        d.setAmount(e.getAmount());
        d.setDate(e.getDate());
        d.setDescription(e.getDescription());
        if (e.getUser() != null) d.setUserId(e.getUser().getId());
        if (e.getCategory() != null) d.setCategoryId(e.getCategory().getId());
        return d;
    }

}
