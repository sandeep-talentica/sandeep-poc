define([ "app", "models/SessionModel","views/searchView",
		'jquery-cookie'],
		function(app, sessionmodel,searchView
				) {
	Backbone.View.prototype.close = function(){
	    //  this.remove();
	      this.unbind();
	      if (this.onClose){
	       this.onClose();
	      }
	    };
			var AppRouter = Backbone.Router.extend({
				initialize : function() {

				},
				routes : {
					"search":"vendorSearch"
				},

				



				vendorSearch : function(){
			    	if(!app.searchView){
			    		 app.searchView=new searchView();
					}
			    	app.searchView.setElement($('#maincontainer')).render();		    	

				}

			});
			return AppRouter;
		});