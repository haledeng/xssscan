// js XSS高危函数黑名单
exports.blackList = {
	// 高危属性
	property:[
	'innerHTML',
	'innerText',
	'outerText',
	'value',
	'src',
	'href',
	'action',
	'outerHTML',
	'title',
	'alt',
	'text'
	],
	// 高危方法
	method:[
	'eval',
	'appendChild',
	'html',
	'append',
	'prepend',
	'before',
	'after',
	'globalEval',
	'new Function',
	'val'
	]
};

// 过滤规则，可以在调用中进行修改配置
exports.filter = {
	// 扫描文件后缀名
	extension:['.html', '.js', '.xhtml', '.css'], 

	// 需要过滤的文件夹
	noScanDir:['svn', 'image', 'images','video', 'flash', 'pics' ,'.idea','img']
};

// Log 
// exports.logDir = 'd:/nodejs/results/abc';

// 显示的代码行数
exports.codeLineLen = 5;

