package com.emp.view.presentation;

import java.util.ArrayList;
import java.util.List;

public class EmpSearchResponse {

	Integer iTotalRecords;
	Integer iTotalDisplayRecords;
	Integer iDisplayLength;
	List<EmpObject> aaData = new ArrayList<EmpObject>();

	public Integer getiDisplayLength() {
		return iDisplayLength;
	}

	public void setiDisplayLength(Integer iDisplayLength) {
		this.iDisplayLength = iDisplayLength;
	}	

	public List<EmpObject> getAaData() {
		return aaData;
	}

	public void setAaData(List<EmpObject> aaData) {
		this.aaData = aaData;
	}

	public Integer getiTotalRecords() {
		return iTotalRecords;
	}

	public void setiTotalRecords(Integer iTotalRecords) {
		this.iTotalRecords = iTotalRecords;
	}

	public Integer getiTotalDisplayRecords() {
		return iTotalDisplayRecords;
	}

	public void setiTotalDisplayRecords(Integer iTotalDisplayRecords) {
		this.iTotalDisplayRecords = iTotalDisplayRecords;
	}
	
	
}
