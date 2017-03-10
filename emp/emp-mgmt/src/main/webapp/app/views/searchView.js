define(["text!templates/emp-search.html", "backbone","app","models/searchModel","text!templates/empSearchResults.html",
           "jquery.dataTables",'dataTables.fixedColumns','dataTables.fixedHeader.min','dataTables.tableTools','lightGallery','chosen','format-currency','jquery.form' ],
        function(searchPage, Backbone,app,searchmodel,searchResults){

	var SearchView = Backbone.View.extend( {
		initialize: function(){
		},
		el:"#maincontainer",
		events          : {
			'click #searchEmp' : 'searchEmployee'

		},


		data:{},
		model:{},

		render : function () {
			var self = this;
			var mname = null;
			this.template = _.template( searchPage );
			this.$el.html("");
			this.$el.html(this.template());
			console.log("calling search");
			self.searchEmployee();
			return this;
		},

		url :function (){
			var gurl=app.context();
			return gurl;
		},


		searchEmployee : function() {
			var self=this;
			var searchModel= new searchmodel();

			var unindexed_array = $('#emp_search_form').serializeArray();
			$.map(unindexed_array, function(n, i){
				var value=n['value'];
				var name=n['name'];
				if (!name.match("_c$")){
					searchModel.set(name,value);
				}				
			});

			this.model=searchModel;
			$('#renderSearchResults').html(_.template( searchResults )({searchResult:null}));
			var oTable=$('#renderEmpTable').dataTable({

				"bServerSide": true,
				"bFilter": false,
				'bProcessing': true,
				"scrollY": "300px",
				"scrollX": "100%",
				"scrollCollapse": true,
				"paging": false,
				"sAjaxSource": app.context()+ '/home/searchDetails/',
				"sAjaxData" : 'aaData',
                //"iDisplayLength": 10,
                
                "aoColumns": [{"mData": "empid","sTitle": "Id" ,"bSortable":false},
				                {"mData": "name","sTitle":"Name","bSortable":false},
				                 {"mData": "designation","sTitle":"Designation","bSortable":false},
				               ],

				                               "fnServerData": function(sSource, aoData, fnCallback, oSettings) {
				                            	   var paramMap = {};
				                            	   for ( var i = 0; i < aoData.length; i++) {
				                            		   paramMap[aoData[i].name] = aoData[i].value;
				                            	   }
				                            	   var pageSize = paramMap.iDisplayLength;
				                            	   var start = paramMap.iDisplayStart;
				                            	   var pageNum = (start / pageSize);//(start == 0) ? 1 : (start / pageSize) + 1; // pageNum is 1 based
				                            	   var sortCol = paramMap.iSortCol_0;
				                            	   var sortDir = paramMap.sSortDir_0;
				                            	   var sortName = paramMap['mDataProp_' + sortCol]; 
				                            	   self.model.set("sortDir",sortDir);
				                            	   self.model.set("sortName",sortName);
				                            	   self.model.set("pageNum",pageNum);
				                            	   self.model.set("pageSize",pageSize);

				                            	   $.ajax({
				                            		   "dataType": 'json',
				                            		   "contentType": "application/json",
				                            		   "type": "POST",
				                            		   "url": sSource,
				                            		   "data": JSON.stringify(self.model),
				                            		   "success": function(res){
				                            			   res.iTotalRecords = res.iTotalRecords;
				                            			   res.iTotalDisplayRecords = res.iTotalRecords;
				                            			   if(res.iTotalDisplayRecords==null){
				                            				   var mess="<label style='color:red;font-size:160%'>No records found</label>";
				                            				   $('#renderSearchResults').html(mess);



				                            			   }else{
				                            				   fnCallback(res);

				                            			   }

				                            		   },
				                            		   "error": function(res){
				                            			   console.log("error");
				                            		   }

				                            	   });
				                               },"fnDrawCallback": function(oSettings) {

											      }


			});


		}//end
		
	});
	return SearchView;
});