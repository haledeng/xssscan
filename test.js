var xss = require('xssscan');
var directory = "d:/nodejs/jsxss";
var cfg = {
	is_$: false,
	is_expression: false
};

xss.cfg(cfg);
xss.scan(directory, function(result){
	console.log(result);
});




