xssscan
=======
功能：

脚本文件静态xss扫描。

安装：

    npm install xssscan

调用：

    var xss = require('xssscan');

对外接口:

    // 是否扫描$符号和css中expression
    xss.cfg({is_$:true, is_expression:true});
    /*
    ** dir {string} 需要扫描的目录
    ** callback 回调函数
    */
    xss.scan(dir, function(r){
        
    });


