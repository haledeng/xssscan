var beautify = require('js-beautify').js_beautify,
	fs = require('fs'),
	path = require('path');

exports.uncompress = function(filename){
	var data = fs.readFileSync(filename, 'utf-8'),
		fileArr = [] ,
		outname,
		dirname = path.dirname(filename);
	data = beautify(data, {indent_size: 4});

	filename = path.basename(filename);
	fileArr = filename.split('.').slice(0,-1);

	// name of new file
	if(fileArr[fileArr.length - 1] === 'min'){
		outname = fileArr.slice(0, -1).join('.') + '.js';
	}else{
		outname = fileArr.join('.') + '.debug.js';
	}

	// write to new file
	fs.writeFile(path.join(dirname, outname), data);
	return outname;
};