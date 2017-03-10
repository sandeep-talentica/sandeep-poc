define([ "backbone", "app" ], function(Backbone, app) {
	var searchModel = Backbone.Model.extend({

		initialize: function () {
			_.bindAll(this);
        },
		
	/*	defaults : {
			contactName : null,
			contactType:null,
			objectId:null,
			createdBy:null
		},*/
		
		url :function (){
			var gurl=app.context();
			return gurl;
		},
		
		searchEmployee: function(opts,callback){
			
			var postdata=opts.attributes;
			
			$.ajax({
	                url: this.url()+'/home/searchDetails/',
	                contentType: 'application/json',
	                dataType:'json',
	                type: 'POST',
	                data: JSON.stringify(postdata),
	                success: function(res){
	                	//alert(res);
	                    if(res){
	                        callback.success('',res);
	                    }else{
	                        callback.error('',res);
	                    	//callback.error('','No Matching records found');
	                    }
	                },
	                error: function(res){
	                    callback.error('','Failed');
	                }
	            });
        }
          
	});

	return searchModel;

});