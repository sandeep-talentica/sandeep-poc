package com.emp.repositories;

import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;

import com.emp.entity.Employee;

public interface EmployeeRepository extends
PagingAndSortingRepository<Employee, Long>  {

	@Query("select emp from Employee emp where (:empid is null or emp.empid = :empid)")
	List<Employee> search(@Param("empid") String empid,
			Pageable pageable);

	@Query("select emp from Employee emp where (:empid is null or emp.empid = :empid)")
	List<Employee> search(@Param("empid") String empid);
	
	public Employee findByEmpid(String empid);
}
