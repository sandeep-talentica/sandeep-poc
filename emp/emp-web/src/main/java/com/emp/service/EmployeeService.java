package com.emp.service;

import java.util.List;
import java.util.Map;

import com.emp.entity.Employee;

public interface EmployeeService {
	
	public List<Employee> search(Map<String, Object> values);

	public List<Employee> searchWithPagination(
			Map<String, Object> values);

}
