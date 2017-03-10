/**
 * @desc        configure aliases and dependencies
 */

if (typeof DEBUG === 'undefined') DEBUG = true;

require.config({
    baseUrl: './app',

    paths: {

    	'jquery'                     : '../assets/js/lib/jquery',
        'underscore'            : '../assets/js/lib/underscore',         
        'backbone'              : '../assets/js/lib/backbone',
        'text'                  : '../assets/js/lib/text',
        'jquery-cookie'         :'../assets/js/lib/modifiedplugins/jquery.cookie',
        'lightGallery'			:'../assets/js/lib/lightGallery',
        'app1':'../assets/js/lib/app1',
        'jquery-ui-1.10.3.custom.min':'../assets/js/lib/jquery-ui-1.10.3.custom.min',
        'bootstrap.min':'../assets/js/lib/bootstrap.min',
        'bootstrap-datepicker':'../assets/js/lib/bootstrap-datepicker',
        'bootstrap-hover-dropdown.min':'../assets/js/lib/bootstrap-hover-dropdown.min',
        'bootstrap-select.min':'../assets/js/lib/bootstrap-select.min',
        'canvas-to-blob.min':'../assets/js/lib/canvas-to-blob.min',
        'components-dropdowns':'../assets/js/lib/components-dropdowns',
        'components-pickers':'../assets/js/lib/components-pickers',

        'form-fileupload':'../assets/js/lib/form-fileupload',
        'form-validation':'../assets/js/lib/form-validation',
       // 'jquery-1.10.2.min'              	: '../assets/js/lib/jquery',
        'hide-show':'../assets/js/lib/hide-show',
        'jquery.blockui.min':'../assets/js/lib/jquery.blockui.min',
        'jquery.dataTables':'../assets/js/lib/jquery.dataTables',
        'dataTables.fixedColumns':'../assets/js/lib/dataTables.fixedColumns',
        'dataTables.fixedHeader.min':'../assets/js/lib/dataTables.fixedHeader.min',
        'dataTables.tableTools':'../assets/js/lib/dataTables.tableTools',
        'DT_bootstrap':'../assets/js/lib/DT_bootstrap',
        'jquery.fileupload':'../assets/js/lib/jquery.fileupload',
        'jquery.fileupload-image':'../assets/js/lib/jquery.fileupload-image',
        'jquery.fileupload-process':'../assets/js/lib/jquery.fileupload-process',
        'jquery.fileupload-ui':'../assets/js/lib/jquery.fileupload-ui',
        'jquery.fileupload-validate':'../assets/js/lib/jquery.fileupload-validate',
        'jquery.multi-select':'../assets/js/lib/jquery.multi-select',
        'jquery.slimscroll.min':'../assets/js/lib/jquery.slimscroll.min',
        'jquery.ui.widget':'../assets/js/lib/jquery.ui.widget',
        'jquery.uniform.min':'../assets/js/lib/jquery.uniform.min',
        'jquery.validate.min':'../assets/js/lib/jquery.validate.min',

        'load-image':'../assets/js/lib/load-image',
        'load-image.min':'../assets/js/lib/load-image.min',
        'load-image-exif':'../assets/js/lib/load-image-exif',
        'load-image-ios':'../assets/js/lib/load-image-ios',
        'load-image-meta':'../assets/js/lib/load-image-meta',
        'login':'../assets/js/lib/login',
        'select2.min':'../assets/js/lib/select2.min',
        'table-managed':'../assets/js/lib/table-managed',
        'tmpl.min':'../assets/js/lib/tmpl.min',
        'jquery.form':'../assets/js/lib/modifiedplugins/jquery.form',
        'jquery.bxslider':'../assets/js/lib/jquery.bxslider',
        'polyglot': '../assets/js/lib/polyglot.min',
        'chosen': '../assets/js/lib/chosen.jquery.min',
        'multiple.select': '../assets/js/lib/multiple.select',
        'jquery.stickyheader': '../assests/js/lib/jquery.stickyheader',
        'format-currency'       : '../assets/js/lib/jquery.formatCurrency-1.4.0.min',
        //'datatable-input-pagination' : '../assets/js/lib/datatable-input-pagination',
        'parsley.min': '../assets/js/lib/parsley.min',
        'async' : '../assets/js/lib/async'
    },

    // non-AMD lib
    shim: {
        
    	'underscore'            : {deps : ['jquery'], exports  : '_' },
        'backbone'              : { deps : ['underscore','jquery'], exports : 'Backbone' },
        //'main'					:{deps:['config','backbone','underscore', 'jquery-1.10.2.min']},
        'jquery-cookie':["jquery"],
       // 'dataTables.fixedColumns':["jquery-1.10.2.min","jquery.dataTables"],
        "jquery-ui-1.10.3.custom.min": ["jquery"],
        "bootstrap.min": ["jquery"],
        "bootstrap-hover-dropdown.min": ["jquery"],
        'bootstrap-select.min': ["jquery"],
        'jquery.blockui.min':["jquery"],
        "bootstrap-datepicker": ["jquery"], 
        "hide-show": ["jquery"],
        "jquery.slimscroll.min": ["jquery"],
        "jquery.validate.min": ["jquery"],        

        "jquery.fileupload-ui": ["jquery"],

        "jquery.fileupload": ["jquery"],
        "load-image": ["jquery"],
        "jquery.fileupload-process": ["jquery"],
        "jquery.fileupload-image": ["jquery"],        

        "jquery.uniform.min": ["jquery"],
        "jquery.bxslider":["jquery"],
        "select2.min": ["jquery"],
        "lightGallery":["jquery"],
        "jquery.dataTables": ["jquery"],
      //  "DT_bootstrap": ["bootstrap.min","jquery.dataTables"],
        "table-managed": ["jquery"],
        "dataTables.fixedHeader.min":["jquery"],
        "dataTables.tableTools":["jquery"],
 
        "jquery.multi-select":["jquery"],
        
        "app1": ["jquery"],
        "jquery.form":["jquery"],
        "polyglot": { exports: 'Polyglot'},
        "chosen": ["jquery"],
        "jquery.stickyheader" : ["jquery"],
        "format-currency" : ["jquery"],
       // "datatable-input-pagination" :  ["jquery-1.10.2.min"],
        "parsley.min" :["jquery"]
 }

});
requirejs(["../assets/js/app/main1"]);
