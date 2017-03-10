package com.emp.view.controllers;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.emp.entity.Employee;
import com.emp.service.EmployeeService;
import com.emp.view.presentation.EmpObject;
import com.emp.view.presentation.EmpSearchRequest;
import com.emp.view.presentation.EmpSearchResponse;

@RestController
@RequestMapping({ "/api/v1/home", "/home" })
public class HomeController {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(HomeController.class);
	
	@Autowired
	private EmployeeService employeeService;
	
	@RequestMapping(value = "/searchDetails", method = RequestMethod.POST)
	public EmpSearchResponse getComps(@RequestBody EmpSearchRequest request) {
		LOGGER.info("In home controller");
		EmpSearchResponse response = new EmpSearchResponse();
		Map<String, Object> paramMap = new HashMap<String, Object>();
		
		if(isNullString(request.getEmpid())){
			request.setEmpid(null);
		}
		
		paramMap.put("empid", request.getEmpid());
		paramMap.put("pageNum", request.getPageNum());
		paramMap.put("pageSize", request.getPageSize());
		paramMap.put("sortDir", request.getSortDir());
		paramMap.put("sortName", request.getSortName());
		
		List<Employee> empList = employeeService
				.searchWithPagination(paramMap);

		List<Employee> empListTotal = employeeService
				.search(paramMap);

		List<EmpObject> listEmpObj = new ArrayList<EmpObject>();
		
		for (Employee emp : empList) {
			
			EmpObject empObj = new EmpObject();
			empObj.setEmpid(emp.getEmpid());
			empObj.setName(emp.getName());
			empObj.setDesignation(emp.getDesignation());
			
			listEmpObj.add(empObj);
		}
		
/*		EmpObject emp1 = new EmpObject();
		EmpObject emp2 = new EmpObject();
		emp1.setEmpid("123");
		emp1.setName("Anruaj");
		emp2.setEmpid("234");
		emp2.setName("Sanddep");
		emp2.setDesignation("SE");
		listEmpObj.add(emp1);listEmpObj.add(emp2);
*/
		if (!listEmpObj.isEmpty()) {
			response.setAaData(listEmpObj);
			response.setiTotalRecords(empListTotal.size());
			response.setiDisplayLength(10);
			response.setiTotalDisplayRecords(listEmpObj.size());
		}
		return response;
		
	}
	
	private boolean isNullString(String str) {
		if (str == null || "".equals(str.trim())) {
			return true;
		} else {
			return false;
		}
	}
	
}
