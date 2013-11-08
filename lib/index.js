/*
** by helondeng
** 2013/08/04
** 功能：扫描dirscan过滤之后提供的文件列表，匹配高危函数，过滤注释等，提供接口
** 接口：
** config, filter 配置扫描时需要过滤的文件后缀名和目录，支持两种形式的参数传递
** xssLater, scan 扫描并回调处理扫描结果
*/
;(function(definition){
	var hasExports = typeof module !== 'undefined' && module.exports,
		hasDefine = typeof define === 'function';
	if(hasExports){
		module.exports = definition();
	}else if(hasDefine){
		define(definition);
	}else{
		this['scriptScan'] = definition();
	}
}).call(this, function(){
	var blackList = require('./config.js'),
		black = blackList.blackList,
		property = black.property,
		file = require('./dirScan.js'),
		proxy = require('eventproxy'),
		ep = new proxy(),
		method = black.method;
	/*
	** 扫描脚本文件，根据规则匹配
	*/
	// val=location.hash || location.href; m[1]
	var LOCATION = /([a-zA-Z0-9_-]+)\s*=\s*location/i;

	// val = document.getElement || $().val()   m[1] || $()  (自定义)
	// var INPUT = /([a-zA-Z0-9_-]+)\s*=\s*(document\.getElement(s)?By|\$\((\'|\")\w+(\'|\")\)\.val\(\)|\$\(\w+\))/;
	var INPUT1 = /([a-zA-Z0-9_-]+)\s*=\s*document\.getElement[a-zA-z]+\(([a-zA-Z0-9_\'\"-]+)\)/;
	var INPUT2 = /([a-zA-Z0-9_-]+)\s*=\s*\$\(([a-zA-Z0-9_\'\"-]+)\)/;

	// 函数调用  这个暂时没用上，在后面的back中过滤掉了
	// var INPUT3 = /([a-zA-Z0-9_-]+)\s*=\s*([a-zA-Z0-9_]*\([a-zA-Z0-9_][a-zA-Z0-9_,\s]{0,}\))/;

	// val = val.replace('&lt;','<').replace(/&gt;/gmi, '>')   顺序随意 m[1]
	var CGI = /([a-zA-Z0-9_-]+)\s*=\s*([a-zA-Z0-9_-]+)(\.replace\((\'|\"|\/)?&lt;(\'|\"|\/g?i?m?)\s*,\s*(\'|\")<(\'|\")\)|\.replace\((\'|\"|\/)&gt;(\'|\"|\/g?i?m?)\s*,\s*(\'|\")>(\'|\")\)){1,}/;

	// 高危属性漏洞  m[2]  innerHMML, value, href, src
	// 注意字符串连接操作
	var PRO_REG = new RegExp("\\\.(" + property.join('|') + ")\\\s*=\\\s*(.*\\\s*\\\+\\\s*)?([a-zA-Z0-9_-]+)",'i');

	// 高危函数漏洞  m[2] appendChild()  html()
	var MHD_REG = new RegExp("\s*(" + method.join('|') + ")\\\((.*\\\s*\\\+\\\s*)?([a-zA-Z0-9_-]+)\\\)",'i');

	// 变量的赋值传递
	var EQUAL = /([a-zA-Z0-9_-]+)\s*=\s*([^function'"{[\s][a-zA-Z0-9_\(\)-]*)(;)?$/;

	// 函数  
	// func = functino(){}   
	var FUNC1 = /([a-zA-Z0-9_-]+)\s*=\s*function\s*\(\w*\)/i;
	// func : function()
	var FUNC2 = /([a-zA-Z0-9_-]+)\s*:\s*function\s*\(\w*\)/i;
	// function func()
	var FUNC3 = /function\s([a-zA-Z0-9_-]+)\s*\(\w*\)/i;

	// CSS expression
	var EXPRESSION = /expression\(/i;


	var is_expression = blackList.is_expression;

	/*
	** 数据来源匹配
	** val = xss
	** @param string str  行代码字符串
	** @return string   赋值变量
	*/
	var getInput = function(str){
		var m = str.match(LOCATION) || str.match(INPUT1) || str.match(CGI) || str.match(INPUT2);
		if(m){
			return [m[1], m[2]];
		}
	};

	/*
	** 数据流向匹配
	** xss = val
	** @param string str  行代码字符串
	** @return string   赋值变量
	*/
	var getOutput = function(str){
		var m = str.match(PRO_REG) || str.match(MHD_REG);
		if(m){
			return [m[1], m[3]];
		}
	}

	/*
	** 直接高危赋值，不经过中间变量
	** div.innerHTML = location.href
	*/
	var direct = function(str){	
		if((LOCATION.test(str) || INPUT1.test(str) || INPUT1.test(str) || CGI.test(str)) && (PRO_REG.test(str) || MHD_REG.test(str))){
			return true;
		}
		return false;
	}

	/*
	** 变量赋值
	** a = xss变量
	** c = a
	** 将c也加入高危列表
	*/
	var equal = function(str){
		var m = str.match(EQUAL);
		if(m){
			return [m[1], m[2]];
		}
	};

	/*
	** 匹配函数表达式
	** @return undefined || function name
	*/
	var func_match = function(str){
		var m = str.match(FUNC1) || str.match(FUNC2) || str.match(FUNC3);
		if(m){
			return m[1];
		}
	}

	var expression_func = function(){};


	/*
	** 删除左边空格
	*/
	var trim_left = function(str){
		return str.replace(/^\s*/g,'');
	};

	/*
	** 删除右边空格
	*/
	var trim_right = function(str){
		return str.replace(/\s*$/g,'');
	}

	// 多行注释不支持嵌套，因此 multicomment中只要存储一个元素即可
	var multicomment = [];

	// push 代码行
	var codes = [];

	// push的最大代码行数
	var LENGTH = blackList.codeLineLen;

	// 两个变量同名，但是不在同一个函数中，也就不在一个上下文中 记录函数名
	var func = [];

	// 上下文 记录{}
	var context = [];

	// 记录遍历line是文件的变化，用于清空codes
	var lastFile;

	/*
	** 扫描行代码，匹配数据来源和数据流向 
	** @param string f 文件路径
	** @param string no 代码行号 
	** @param string line 行代码字符串
	** @return 扫描结果
	** { path: 'abc\\b.js', row: 8, variable: 'v1', flag: 'i' } 
	** { path: 'abc\\b.js', row: 17, variable: 'v1', flag: 'o' }
	** 过滤注释， 单行注释和多行注释
	** 匹配漏洞模式
	** 两个同名变量在不同函数内部的混淆问题，记录变量所属的函数
	*/
	var handler_line =  function(f, no, line){
		if(lastFile != f){
			codes = [];
			lastFile = f;
		}
		if(codes.length == LENGTH){
			codes.shift();
		}
		codes.push(line);
		line = trim_left(line);
		line = trim_right(line);
		// 赋值最短 a=b  注释  HTML  多行注释 /*
		if(line && line.substr(0,1) !== '<' && multicomment.length == 0 && line.length>=3 && line.substr(0,2) !== '//'  && line.substr(0,2) !== '/*' ){
			var i = getInput(line),
			o = getOutput(line),
			d = direct(line),
			e = equal(line),
			css = expression_func(line);
			obj = {},
			fn = func_match(line),
			// current function
			fname = func.length>0?func[func.length-1]:undefined;
			// global
			obj['func'] = fname? fname : 'doc';
			// find function definition
			if(fn !== undefined){
				func.push(fn);
				fname = fn;
			}
			// 处理函数内部的｛｝
			if(fname && line.indexOf('{')>-1){
				context.push(1);
			}
			if(fname && line.indexOf('}')>-1){
				context.pop();
			}
			// function definition end
			if(context.length === 0){
				func.pop();
			}
			// 直接XSS漏洞
			if(d === true || css === true){
				obj['path'] = f;
				obj['row'] = no;
				obj['flag'] = 'd';
				if(css){ 
					obj['method'] = 'expression';
				}
				obj['codes'] = [].concat(codes);
				return obj;
			}
			if(i || o){
				obj['path'] = f;
				obj['row'] = no;
				if(i){
					obj['variable'] = i[0];
					obj['from'] = i[1];
					obj['flag'] = 'i';
					obj['codes'] = [].concat(codes);
				}else{
					obj['variable'] = o[1];
					obj['flag'] = 'o';
					obj['method'] = o[0];
					obj['codes'] = [].concat(codes);
				}
				return obj;
			}
			// 变量赋值
			if(e){
				obj['path'] = f;
				obj['row'] = no;
				obj['variable'] = e[1];
				obj['toVariable'] = e[0];
				obj['flag'] = 'e';
				return obj;
			}
		}
		// 注释开始 剔除嵌套
		else if(line.substr(0,2) === '/*' && multicomment.length == 0){
			multicomment.push(1);
			// 同一行内
			if(line.indexOf('*/')>-1){
				multicomment.pop();
				multicomment.length = 0;
			}

		}
		// 注释结束
		// line.substr(line.length-2, 2) === '*/'
		else if(line.indexOf('*/')>-1 && multicomment.length == 1){
			multicomment.pop();
			multicomment.length = 0;
		}	
	};

	var indexOf = file.indexOf;

	/*
	** 处理变量跟踪的问题，将 a = xss, b = a, xss = b
	** 处理后的结果  
	  	{ path: 'D:\\nodejs\\jsxss\\url.html',
	    row: 3,
	    variable: 'hs&h&s',     变量的赋值去向，这几个变量有相同的取值
	    flag: 'i' },
	*/
	var result_clean = function(r){
		if(r){
			(function(){
				var input = r['i'],
					// 变量赋值
					e = r['e'],
					l = input.length,
					item;
				for(var k=0;k<l;k++){
					item = input[k];
					for(var j = 0,el = e.length;j<el;j++){
						var rtn = e[j];
						if(item.path == rtn.path && indexOf(item.variable.split('&'), rtn.variable) !== -1){				
							r['i'][k].variable = r['i'][k].variable + '&' + rtn.toVariable;
						}
					}
				}
			})();
		}
		// 内存回收
		r['e'] = [];
		delete r['e'];
		return r;
	};

	/*
	** 输出结果中查找XSS漏洞，同一变量在=左边被赋值  x = input || location || cgi.replace 
	** 同时也在等号右边赋值给innerHTML || value || href等（黑名单函数）
	** i 表示变量在左边的扫描结果
	** o 表示在右边的结果
	** d 表示直接xss漏洞  div.innerHTML = location.href
	** @param object r  扫描结果对象，格式
	   { i:
	   [ { path: 'abc\\a.js', row: 9, variable: 'val', flag: 'i' },
	     { path: 'abc\\b.js', row: 8, variable: 'v1&hs', flag: 'i' } ],
	  o: [ { path: 'abc\\b.js', row: 17, variable: 'v1', flag: 'o' } ],
	  d: [{ path: 'abc\\b.js', row: 17,flag: 'o'}] /
	  }
	** @return array  XSS漏洞 格式
	  [ { path: 'jsxss\\cgi.html', row: '8&9', variable: 'cgi' },
	  { path: 'jsxss\\input.html', row: '9&11', variable: 'value' },
	  { path: 'jsxss\\url.html', row: '45&46', variable: 'hs' } ]
	*/
	var result_match = function(r){
		if(!r || typeof r !== 'object' || !r['i'] || !r['o']){
			return;
		}
		var i = r['i'],  // input 数组
			o = r['o'],  // output数组
			d = r['d'],
			iL = i.length,
			oL = o.length,
			dL = d.length,
			iV, 
			oV,
			dV,
			xss = [];
		for(var k=0;k<iL;k++){
			// 格式 { path: 'abc\\b.js', row: 8, variable: 'v1', flag: 'i' } 
			iV = i[k];
			for(var j=0;j<oL;j++){
				// 格式{ path: 'abc\\b.js', row: 17, variable: 'v1', flag: 'o' }
				oV = o[j];
				// 在同一个文件 && 变量名一致
				if(iV.path === oV.path && iV.func === oV.func && indexOf(iV.variable.split('&'), oV.variable) !== -1){
					//XSS
					var obj = {};
					obj['path'] = iV.path;
					obj['source'] = iV.row;
					obj['destination'] = oV.row;
					obj['variable'] = iV.variable;
					obj['from'] = iV.from;
					obj['method'] = oV.method;
					var l = parseInt(oV.row) - parseInt(iV.row);
					if(l < LENGTH && l > 0){
						obj['codes'] = oV.codes.join('\n');
						//obj['codes'] = iV.codes.slice(l - LENGTH).join('\n') + "\n" + oV.codes.slice(-l).join('\n');
					}else{
						obj['codes'] = iV.codes.join('\n') + "\n\n" +  oV.codes.join('\n');
					}
					
					xss.push(obj);
				}
			}
		}
		// 直接XSS漏洞  div.innerHTML = location.href
		for(k=0;k<dL;k++){
			dV = d[k];
			var obj = {};
			obj['path'] = dV.path;
			//obj['row'] = dV.row;
			obj['source'] = dV.row;
			obj['destination'] = dV.row;
			obj['method'] = dV.method;
			obj['codes'] = dV.codes.join('\n');
			xss.push(obj);
		}
		return xss;
	};

	/*
	** 只做一次变量回溯
   	**  a = "aaaaaa"   查看  "aaaaaa" 里面是否有<>或者 &lg; &gt;
   	**  a = func(b[,c,d]) 查看变量 b,c,d 定义中是否含有<>或者 &lg; &gt;
    */
    var back = function(r, cb){
    	var i=0,
    		l = r.length,
    		item,
    		xss = [],
    		fs = require('fs'),
    		readline = require('readline');
    	ep.after('back', l, function (list) {
			 cb(xss);
		});
    	for(;i<l;i++){
    		item = r[i];
    		if(!item.from){
    			xss.push(item);
    			ep.emit('back', item);
    			continue;
    		}
    		var variable = item.from;
    		// 来源是字符串
    		if(variable.indexOf("'") > -1 || variable.indexOf('"') > -1){
    			xss.push(item);
    			ep.emit('back', item);
    		}
    		// 来源是变量，回溯查找变量来源
    		else{
    			// 由于readFile函数本身的async，所以读取的都是最后一条记录
    			// 这里需要使用闭包
    			(function(obj){   				
    				fs.readFile(obj.path,function(err,data){						
	    				data = data.toString();
	    				var v = obj.from,
	    					reg = new RegExp(v + "\\\s*=\\\s*([^\(]*)(;)",''),
	    					m;
	    				var inp = new RegExp(v + "\\\s*=\\\s*(document\\\.getElement(s)?By|\\\$\\\(\\\w+\\\))",'');
	    				// 注释
	    				data = data.replace(/\/\/.*\r\n/mg,'').replace(/\/\*[\/]*\*\//gm, '');
	    				// 变量包含 <>
	    				if(m = data.match(reg)){
	    					// m[1] = string
	    					// m[1] = input.value
	    					if(m[1].indexOf("'") > -1 || m[1].indexOf('"') > -1 || m[1].indexOf(".value")){
								xss.push(obj);
							}
						}		
						// 变量 = $()   document.getElement			
						else if(inp.test(data)){
							xss.push(obj);
						}
						else{
							// 函数调用											
							var func_call = new RegExp(v + "\\\s*=\\\s*[a-zA-Z0-9_]*\\\(([a-zA-Z0-9_,\s]+)\\\)",'');
							if(m = data.match(func_call)){
								//console.log('123'+ m[1] + v);
								if(trim_right(trim_left(m[1]))!==''){
									//console.log()
									var args = [];
									// 多个参数
									if(m[1].indexOf(',')>-1){
										var tmp = m[1].split(',');
										(function(){
											// 去掉前后空格
											for(var k=0,tmpL = tmp.length;k<tmpL;k++){
												args.push(trim_right(trim_left(tmpL[i])));
											}
										})();
									}
									// 一个参数
									else{
										args.push(trim_right(trim_left(m[1])));
									}
									// 变量回溯
									for(var k=0,argsL=args.length;k<argsL;k++){
										//  document.getElement   $()  <tag>
										var ipt = new RegExp(args[k] + "\\\s*=\\\s*(document\\\.getElement(s)?By|\\\$\\\(\\\w+\\\)|[^><]*<[^>]*>)",'');
										if(ipt.test(data)){
											xss.push(obj);
											break;
										}
									}
								}
							}
						}
						ep.emit('back');
    				});
    			})(item);
    		}
    	}	
    }; 

	var scriptScan = {};

	/*
	** @parem string dir  需要扫描的目录
	** @param function cbfunc  回调函数  处理扫描结果
	*/
	scriptScan.xss =  function(dir, cbfunc){

		/*
		** css expression
		** 分支定义函数，不需要在函数内容每次都用if来判断
		*/
		if(!is_expression){
			expression_func = function(){
				return false;
			};
		}else{
			expression_func = function(str){
				var m = str.match(EXPRESSION);
				return (m?true:false);
			};
		}
		file.line(dir, handler_line, function(r){
			// console.log(r);
			r = result_clean(r);
			// xss扫描结果		
			var xss = result_match(r);
			//console.log(xss);
			// 过滤误报
			back(xss, function(l){
				// 回调函数处理结果
				cbfunc(l);
			});
		});
	};

	// async
	var later = function(fn){
		setTimeout(fn, 0);
	};

	/*
	** make xss async
	*/
	scriptScan.xssLater = function(dir, cbfunc){
		var self = this;
		later(function(){
			self.xss.call(self, dir, cbfunc);
		});
	};

	/*
	** 配置$是否为高危函数
	** 默认为高危漏洞
	*/
	scriptScan.is_$ = function(t){
		// 默认处理放在其他位置了
		// t = (t === undefined)? true : t;
		if(t === false || t === 0){
			INPUT2 = INPUT1;
		}else{
			INPUT2 = /([a-zA-Z0-9_-]+)\s*=\s*\$\(([a-zA-Z0-9_\'\"-]+)\)/;
		}
	};

	scriptScan.is_expression = function(t){
		if(typeof t === 'boolean'){
			is_expression = t;
		}
		
		///console.log(is_expression)
	}

	// alias
	scriptScan.scan = scriptScan.xssLater;

	scriptScan.cfg = function(cfg){
		this.is_$(cfg.is_$);
		this.is_expression(cfg.is_expression);
	}

	return scriptScan;
});

