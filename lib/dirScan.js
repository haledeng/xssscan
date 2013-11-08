/*
** by helondeng
** 功能：扫描目录下的脚本，根据规则过滤，输出脚本列表，进行脚本行扫描，执行回调
** 接口：
** config 配置扫描时需要过滤的文件后缀名和目录，支持两种形式的参数传递
** line 进行脚本行扫描，执行回调
*/

;(function(definition){
	var hasExports = typeof module !== 'undefined' && module.exports,
		hasDefine = typeof define === 'function';
	if(hasExports){
		module.exports = definition();
	}else if(hasDefine){
		define(definition);
	}
	else{
		this['dirScan'] = definition();
	}
}).call(this, function(){

	var fsys = require('fs'),
		readline = require('readline'),
		proxy = require('eventproxy'),
		filter = require('./config.js').filter,
		ep = new proxy(),
		path = require('path'),
		unpack = require('./unpack.js'),
		dirScan = {};


// 扫描文件的后缀名
dirScan.extension = filter.extension ;
// 需要过滤的目录
dirScan.noScanDir = filter.noScanDir;

var indexOf = function(array, item){
	if(Array.prototype.indexOf){
		return Array.prototype.indexOf.call(array, item);
	}
	
	for(var i=0,l=array.length;i<l;i++){
		if(array[i] ===  item){
			return i;
		}
	}
	return -1;
};

dirScan.indexOf = indexOf;

/*
** 配置后缀名和要过滤的文件夹
*/
dirScan.config = function(){
	var that = dirScan,
		args = arguments,
		len = args.length;
	// 对象形式
	if(len === 1){
		var conf = args[0];
		var toString = Object.prototype.toString;
		// ｛extensioni:[], noScanDir:[]｝
		if(toString.call(conf) === "[object Object]"){
			
			that.extension = conf.extension;
			that.noScanDir = conf.noScanDir;
		}
	}
	// 数组形式 
	else if(len === 2){
		that.extension = args[0];
		that.noScanDir = args[1];
	}
};

/*
** 读取文件内容
** @param string file 待读文件
** @param function callback 读取文件中每一行的回调函数
** no return
*/
dirScan.readfile = function(file, callback){
	var stream = fsys.createReadStream(file);
	var rd = readline.createInterface({
		input: stream,
		output: process.stdout,
		terminal: false
	});

	var no = 1;
	rd.on('line', function(line){		
		if(typeof callback === 'function'){
			// 回调函数，处理每一行数据， 异步模式
			callback(file, no, line);
		}
		no++;
	});
	// 流关闭
	stream.on('end',function(){
		console.log('file '+file+' has been scanned.');
		rd.close();
		ep.emit('got_file', null);
	});

};

/*
** 记录目录遍历后的结果，由于目录遍历有递归，所以不能直接返回结果
*/
var result = {};

/* 
** 读取目录下面所有文件
** @param string p 目录
** 递归函数，不能直接返回结果，将结果填充到 result
** { abc: [ 'a.js', 'b.js' ],'abc\\ccc': [ 'c.js' ],'abc\\ccc\\ddd': [ 'd.txt' ] }
*/
var read = function(p){	
	var fileList = fsys.readdirSync(p);
	result[p] = [];
	for(var i=0,l=fileList.length;i<l;i++){
		var item = fileList[i],
			ph = path.join(p, item);	
		if(fsys.lstatSync(ph).isDirectory()){
			if(indexOf(dirScan.noScanDir, item) === -1 && indexOf(dirScan.noScanDir, ph) === -1){
				arguments.callee(ph);
			}			
		}else{	
			// 过滤
			if(indexOf(dirScan.extension, path.extname(ph)) !== -1 && item.indexOf('.min.') === -1){
				result[p].push(item);
			}

			// TODO: 仅从文件名判断文件是否压缩过
			if(item.indexOf('.min.') > 0){
				var outname = unpack.uncompress(ph);
				if(indexOf(result[p], outname) === -1){
					result[p].push(outname);
				}
			}	
		}
	}	
};

var getDate = function(){
	var d = new Date();
	return d.getFullYear() +'/'+(d.getMonth()+1)+'/'+d.getDate()+' '+d.getHours()+':'+d.getMinutes()+':'+d.getSeconds()+'\r\n';
}
// 日志
dirScan.addLog = function(log, logPath){
	if(fs === undefined){
		var fs = require('fs');
	}
	log = log + '\r\n';

	fs.appendFile(logPath, log, 'utf8',function(err){

	});
};

/*
** 读取目录下面所有文件
** @param p  目录路径字符串
** return { abc: [ 'a.js', 'b.js' ],'abc\\ccc': [ 'c.js' ],'abc\\ccc\\ddd': [ 'd.txt' ] }
*/
dirScan.files = function(p){
	// var logPath = path.join(require('./config.js').logDir, 'log.txt')
	try{
		var stat = fsys.lstatSync(p);
		if(stat.isFile()){
			//  && indexOf(this.noScanDir, path.dirname(p)) === -1
			if(indexOf(dirScan.extension, path.extname(p)) !== -1){
				result[p] = [];
				result[p].push(path.basename(p));
			}
			// 打 log
			// this.addLog(getDate() + 'Success. file: '+p+' has been scanned.', logPath);
			return result;
		}
		read(p);
		
		// this.addLog(getDate() + 'Success. dir: '+p+' has been scanned.', logPath)
		return result;
	}catch(err){
		//  this.addLog(getDate() + 'error: '+err.message, logPath);
	}

}

/*
** 计算脚本文件数量
** @param object result { abc: [ 'a.js', 'b.js' ],'abc\\ccc': [ 'c.js' ],'abc\\ccc\\ddd': [ 'd.txt' ] }
** @return int 
*/
dirScan.countFiles = function(result){
	var count = 0;
	for(var i in result){
		files = result[i];	
		count += files.length;
	}
	return count;
};

/*
** 读取脚本文件中的每一行
** @param string p 目录  
** || object p 目录对象{ 'abc': [ 'a.js', 'b.js' ],'abc\\ccc': [ 'c.js' ],'abc\\ccc\\ddd': [ 'd.txt' ] }
** @param function cb 读取每一行代码后的回调函数，用于匹配XSS规则
** @param function cb_d 读取完整个目录下面所有脚本文件返回结果之后，进行回调，用于对结果进行处理
** return 
** { i:
   [ { path: 'abc\\a.js', row: 9, variable: 'val', flag: 'i' },
     { path: 'abc\\b.js', row: 8, variable: 'v1', flag: 'i' } ],
  o: [ { path: 'abc\\b.js', row: 17, variable: 'v1', flag: 'o' } ] }
** i 定义了数据来源，包括input, location, cgi吐数据
** o 定义了数据append到页面的流向，包括 innerHTML, html, value等
*/
dirScan.line = function(p, cb, cb_d){
	// 目录 或者扫描目录后的结果
	var result,
		r = {'i':[],'o':[], 'd':[], 'e':[]};
	if(typeof p === 'string' || (p.constructor && p.constructor === 'String')){ 
		result = this.files(p);
	}else{
		result = p;
	}
	// 遍历目录
	// 子目录
	for(var i in result){
		var dir = i,
			files = result[i];	
		// 子目录下的脚本文件
		for(var j=0,l=files.length;j<l;j++){	
			// dir 是目录或者文件					
			var p = dir.indexOf('.')>-1?dir:path.join(dir.toString(), files[j].toString());	
			this.readfile(p, function(f, no, line){
				// 回调
				var rtn = cb(f, no, line);
				rtn && rtn['flag'] && r[rtn['flag']].push(rtn);
			});
		}	
	}
	// 在所有文件的异步执行结束后将被执行
	ep.after('got_file', this.countFiles(result), function (list) {
	    cb_d(r);
	});
};

return dirScan;
});

