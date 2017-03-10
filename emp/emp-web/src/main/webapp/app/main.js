require([ "app","backbone", "underscore", "routers/AppRouter", "models/SessionModel", "polyglot" ],
function(app,Backbone,_, WebRouter, sessionmodel, polyglot) {
	

	
	var buildSessionModel = function() {
		var sessionData = null;
		app.sessionModel = new sessionmodel();
		sessionData = app.sessionModel.getUser();
		app.sessionModel.set({
			userId : sessionData.userId,
			firstName : sessionData.firstName,
			isDeleted : sessionData.isDeleted,
			isInactive : sessionData.isInactive,
			isLocked : sessionData.isLocked,
			lastName : sessionData.lastName,
			userName : sessionData.userName,
			permissions : sessionData.permissions,
			statusCode : sessionData.statusCode,
			message : sessionData.message,
			roles : sessionData.roles
		});
		console.log(app.sessionModel)
	};
	//buildSessionModel();
	// var locale = localStorage.getItem('locale') || 'en';
	 var userLang = navigator.language || navigator.userLanguage; 
	 if(userLang =='undefined'){
		 userLang = "en-US";
	 }
	 var myUrl = '/locales/' + userLang + '.json';
	 
	 $.ajax({
		  url: myUrl,
		  dataType: 'json',
		  async: false,
		  success: function(data) {
			  window.polyglot = new Polyglot({phrases: data});
		  } });
	if(!app.router){
		app.router=new WebRouter();
	}
	Backbone.history.start();
	var current_route = window.location.hash.substr(1);
	if(!current_route){
		app.router.navigate("search",{ trigger:true, replace: true })
	}else{
		app.router.navigate(current_route,{ trigger:true, replace: true })
	}
	
	/*if($.inArray('VendorManagement', app.sessionModel.attributes.permissions)==-1) {
		app.router.navigate("search",{ trigger:true, replace: true });
	} else {
		app.router.navigate("vendor",{ trigger:true, replace: true });
	}*/
});
