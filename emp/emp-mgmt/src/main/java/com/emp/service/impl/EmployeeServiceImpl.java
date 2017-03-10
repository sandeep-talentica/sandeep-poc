package com.emp.service.impl;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.emp.entity.Employee;
import com.emp.repositories.EmployeeRepository;
import com.emp.service.EmployeeService;

@Service
@Transactional("empTransactionManager")
public class EmployeeServiceImpl implements EmployeeService {

	
	@Autowired
	private EmployeeRepository employeeRepository;
	
	public List<Employee> search(Map<String, Object> values) {
		return employeeRepository.search(
				(String) values.get("empid"));
	}

	public List<Employee> searchWithPagination(Map<String, Object> values) {
		Direction sortingDir = null;
		if (values.get("sortDir").toString().indexOf("asc") >= 0) {
			sortingDir = Direction.ASC;
		} else {
			sortingDir = Direction.DESC;
		}
		Sort sort = new Sort(sortingDir, (String) values.get("sortName"));

		Pageable pageable = new PageRequest((Integer) values.get("pageNum"),
				(Integer) values.get("pageSize"), sort);

		return employeeRepository.search(
				(String) values.get("empid"),  pageable);
	}

}
