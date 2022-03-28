# (S4W



# Indice
1. [Info][1]
1. [Problemas sin resolver][2]
	1. [Password Checker][3]
	2. [Turing][4]
3. [Problemas resueltos][5]
	1. [Welcome][6] 
	1. [poem-collection][7]
	2. [checker][8]
	3. [Lazy Leaks][9]
	4. [The Magic Modbus][10]
	5. [Sonicgraphy Fallout][11]
	6. [A Pain in the Bac(Net)][12]

# Info
User: Ellipsis
Sitio: https://ctf.csaw.io/challenges

<br/>
<br/>

# Problemas sin resolver:


## Password Checker

### Qué Hicimos?
- Cuando usamos `strings` con `password_checker` obtenemos `backdoor`: Intentamos usarlo como contraseña pero no sirvió de nada.
- Usamos [`ghidra`][13] para de-compilar el ejecutable `password_checker` y ahí encontramos un espacio en la memoria con el valor `0x64726f7773736170` que representa `drowssap`, que es `password` al revés y es la contraseña correcta (pero ese no es el problema, no hace nada en realidad.)

Hopper:
```C
void backdoor() {
    system("bin/sh");
    return;
}

int init() {
    rax = * __TMC_END__;
    rax = setvbuf(rax, 0x0, 0x2, 0x0);
    return rax;
}

int password_checker() {
    printf("Enter the password to get in: \n>");
    gets(&var_40);
    strcpy(&var_70, &var_40);
    var_A0 = 0x64726f7773736170;
    *(int8_t *)(&var_A0 + 0x8) = 0x0;
    rax = strcmp(&var_70, &var_A0);
    if (rax == 0x0) {
        rax = printf("You got in!!!!"); // <-- No hace nada con la contraseña correcta
    } else {
        rax = printf("This isa not the password");
    }
    return rax;
} 

int main() {
    init();
    main();
}
```

ghidra:
```C
void backdoor(void) {
  system("/bin/sh");
  return;
}

int init(EVP_PKEY_CTX *ctx) {
  int iVar1;
  iVar1 = setvbuf(stdout,(char *)0x0,2,0);
  return iVar1;
}


void password_checker(void) {
  undefined8 local_a8;
  undefined local_a0;
  char local_78 [48];
  char local_48 [60];
  int local_c;
  
  printf("Enter the password to get in: \n>");
  gets(local_48);
  strcpy(local_78,local_48);
  local_a8 = 0x64726f7773736170;
  local_a0 = 0;
  local_c = strcmp(local_78,(char *)&local_a8);
  if (local_c == 0) {
    printf("You got in!!!!"); // <-- No hace nada con la contraseña correcta
  }
  else {
    printf("This is not the password");
  }
  return;
}

undefined8 main(EVP_PKEY_CTX *param_1) {
  init(param_1);
  password_checker();
  return 0;
}
```

### Qué Sabemos?
- Hay una función llamada backdoor() que ejecuta `system("/bin/sh")`, abriendo un lugar (talvez) para comunicarnos con el servidor.
- La contraseña es `backdoor`

#### **setvbuff** -- Controls stream buffering and buffer size.
```C
int setvbuf(
   FILE *stream,
   char *buffer,
   int mode,
   size_t size
);
```

* stream: Pointer to FILE structure.
* buffer: User-allocated buffer.
* mode: Mode of buffering.
* size: Buffer size in bytes. Allowable range: 2 \<= size \<= INT\_MAX (2147483647). Internally, the value supplied for size is rounded down to the nearest multiple of 2.

**Fuente**: [Microsoft][14]


### Ideas:
> Descifrar "backdoor" [name=Karla]
> Investigar cómo acceder a `backdoor()`.
> - Creo que el `strcpy()` en el main puede ser la clave. Tal vez este articulo: [Remote Buffer Overflow Vulnerability][15] 
> - Creo que el que dejaran `0x64726f7773736170` en el código y represente `password` al revés, cuando la contraseña es `password` puede tener que ver. [name=Alex]

### Notas

---
<br/>

## Turing
### ¿Qué hicimos?

### ¿Qué sabemos?

Hay que descifrar `jmodtrr_tdwumtu_cydy_ynsldf`, nos dan como pista `M3 UKW B`

### Ideas

### Notas
> Puse varios links de videos sobre Enigma/Turing en el discord [name=Alex]



---
<br/>
<br/>

# Problemas resueltos:

## Welcome

En el discord que ponen como link, en el chat general la descripción tiene la bandera.

![][image-1]

---
<br/>

## poem-collection

Es un sitio web de poemas. http://web.chal.csaw.io:5003

1. Entramos y hay un error: (php esperaba un valor en la url)

`Warning:  file_get_contents(): Filename cannot be empty in /var/www/html/poems/index.php on line 4`

2. Entramos a `/poems/` con el link que hay entrando. De nuevo hay un error.

http://web.chal.csaw.io:5003/poems/

3. Le damos click a poema1.txt y nos dirige, ahora sin errores a:

http://web.chal.csaw.io:5003/poems/?poem=poem1.txt

4. Claramente en `poem` especificamos el archivo que queremos.

5. Intentamos abrir `flag.txt`

http://web.chal.csaw.io:5003/poems/?poem=flag.txt -- Y no se encuentra. 

6. Intentamos abrir flag.txt un directorio antes (salir de `/poem` para estar en `/`) usando `..` (como para moverse por la terminal)

http://web.chal.csaw.io:5003/poems/?poem=../flag.txt

Y obtenemos la clave.

---
<br/>


## checker

Hay un código de python que encripta un `str` haciendo uso de la función `encode` que a su vez usa `up`, `down`, `right` y `left`.

Código completo original en: https://demo.hedgedoc.org/psK6p75lR8SE7Kq38nfezQ

Cada una de las funciones desempeña un trabajo, un paso en cifrar el mensaje original. Así que solo hacemos todo pero para atrás.

Si algo hacía que un 0 valiera 1; hacemos que ahora haga que un 1 valga 0.

#### up

`up` originalmente recibe un string que analiza letra por letra creando una lista de resultados que después junta de nuevo en un string.

```python
def up(x):
    x = [f"{ord(x[i]) << 1:08b}" for i in range(len(x))]
    return ''.join(x)
```

De la letra obtiene su valor Unicode (`ord`), eso se _mueve_ una posición a la derecha con `<<` (lo que básicamente lo duplica) y eso lo convierte en un string que contiene una representación de en binario (un byte) (`:08b`), que es el Unicode convertido a base 2.

```
"A" -> 65 -> 130 -> "10000010"
```

Entonces hacemos una función que hace lo mismo pero a la inversa. Revisa una cadena de caracteres con ceros y unos y toma bonches de 8 (un byte), lo convierte a un número, hace el _shift_ pero a la izquierda y convierte el resultado a una letra.
```
"10000010" -> 130 -> 65 -> "A" 
```

```python
def un_up(x):
    x = [int(x[i:i+8], 2) >> 1 for i in range(0, len(x), 8)]
    return ''.join(bytes(x).decode("utf-8"))

    # "1000001010000010" -> ["10000010","10000010"] -> [130, 130] -> [65, 65] ->  ["A", "A"] -> "AA"
```

#### down
`down` recibe un string que analizando el código claramente solo espera que contenga ceros y unos. Analiza cada uno y hace que si valía 0 ahora valga uno y viceversa.
```
"0010011" -> "1101100"
def down(x):
    x = ''.join(['1' if x[i] == '0' else '0' for i in range(len(x))])
    return x
```

Así que hacemos una función que haga lo contrario.
```python
def un_down(x):
    x = ''.join(['0' if x[i] == '1' else '1' for i in range(len(x))])
    return x
```

#### right
`right` recibe como argumento un número `n`. Después divide un string desde el caracter en la posición 0 hasta el que está en `n` (le llamaremos *A*) y de `n` hasta el final de la cadena (le llamaremos *B*).

Ya que dividió la cadena hace que pase de ser AB a ser BA

Suponiendo que `n` es 5...
```
"HolaAmigos" -> ["HolaA", "migos"] -> "migosHolaA"
def right(x,d):
    x = x[d:] + x[0:d]
    return x
```

Así que hacemos una función que haga que BA pase a ser AB de nuevo
```python
def un_right(x,d):
    x = x[0:d] + x[d:]
    return x
```

#### left
`left` es una combinación con `right`. Primero hace que se _invierta_ el string `x` que recibe con un número (`d`), que al restársele al tamano del texo, indica dónde se hace la separación en dos del mismo.

Después hace que el resultado de eso sea invertido. (`x[::-1]`)

Suponiendo que `d` es 5 y el texto `"HolaAmigosSoyAlex"` (17 de tamaño)
```
"HolaAmigosSoyAlex" -> "yAlexHolaAmigosSo" -> "oSsogimAaloHxelAy"
def left(x,d):
    x = right(x,len(x)-d)
    return x[::-1]
```
Así que hacemos una que haga lo contrario:
```python
def un_left(x,d):
    x = un_right(x,len(x)-d)
    return x[::-1]
```
Nótese que si en la original hacía `right` nosotros hacemos que haga lo contrario: `un_right`. Dejamos la intrucción que invierte (`x[::-1]`) para que si "ABCD" invertido es "DCBA"; si lo invertimos de nuevo es "ABCD"

#### encode
Y por ultimo juntamos todo en un `decode` que hace todo lo contrario a `encode`

```python
def encode(plain):
    d = 24
    x = up(plain)
    x = right(x,d)
    x = down(x)
    x = left(x,d)
    return x
```
Incluyendo que si al inicio hacía `up` entonces irá al final y será ahora `un_up` y así.

```python
def decode(plain):
    d = 24
    x = un_left(plain,d)
    x = un_down(x)
    x = un_right(x,d)
    x = un_up(x)
    return x
```

Código completo modificado en: https://demo.hedgedoc.org/sL9tMdiTQkCD6ukAEqjMDg

---
<br/>

## Lazy Leaks

Hay un archivo llamado `Lazy_Leaks.pcapng` con extensión `.pcapng`

Investigando:

> Un archivo PCAPNG contiene paquetes de datos capturados a través de una red. El archivo se guarda en el formato PCAP Next Generation (PCAPNG). Los paquetes de datos almacenados en el archivo PCAPNG son utilizados por las aplicaciones del analizador de protocolo de red, como ::Wireshark::, para monitorear y administrar los datos de la red. 

Abrimos el archivo con Wireshark, buscamos `flag` y obtenemos flag como información enviada en un paquete.

![][image-2]

También se puede hacer con `strings` en la terminal y `grep` para filtrar y buscar la palabra `flag` en el texto.

```
strings Lazy_Leaks.pcapng|grep 'flag'
```

![][image-3]


---

<br/>

## The Magic Modbus


> Modbus es un protocolo para que dispositivos y componentes de hardware se comuniquen. Creo, aún no reviso bien [name=Alex]


### Ideas

> Descifrar qué se comunicaron los dispositivos, involucra registros así que peude ser un programa byte por byte o palabras o no sé. [name=Alex]

### Notas
> Hay un video en el discord [name=Alex]

### Solución
Abrimos el paquete con Wireshark. Le damos a Statictics -\> Conversations, donde podemos ver de manera más organizada las conversaciones que se hicieron entre dispositivos.

En la pestaña de TCP hay 3 dispositivos que se comunicaron. Podemos darle follow stream de alguna de esas conversaciones:

![][image-4]

Se puede alcanzar a ver 'I' 'f' 'y' 'o' 'u'...

Lo ponemos en modo HexDump..

![][image-5]

_"If you keep asking questi..."_ , muy bonito pero no es la bandera.

Revisamos otra de las conversaciones:

![][image-6]

Y encontramos: `flag{Ms_Fr1ZZL3_W0ULD_b3_s0_Pr0UD}`

---

<br/>

## Sonicgraphy Fallout

Primero busqué Video en todos los archivos para ver si encontraba algo xd.

```
grep -r . -e "[vV]ideo"
```

Lo que arrojó que el png `Page 7.png` contenía algo. Abrí el archivo con un editor hexadecimal.

Si analizamos [la lista de firmas para archivos][16] podemos ver que `mp4` se compone de `66 74 79 70 69 73 6F 6D`. Lo busqué y encontré.

De ahí, seleccioné un buen cacho de lo que le seguía y lo guardé en otro documento.

![][image-7]

Y si abrimos el resultado tenemos un video que solo se reproduce bien 2 de los 5 segundos porque no sabía hasta donde terminaba así que probablemente no copié todo, pero con tener un frame ya obtenemos la contraseña.

![][image-8]

---

<br/>

## A Pain in the Bac(Net)

Pues abrí Wireshark e identifiqué la parte del paquete que contenía el valor que reportaba el sensor y lo agregué como una columna. También agregué otros datos pero al final no fueron necesarios.

Después ordené las filas de acuerdo al valor reportado.

![][image-9]

Y es muy notable que hay algun dispositivo que mandó 99999.99
Volví a ordenar los paquetes de acuerdo a su número y revisé la zona donde estaba el paquete 2033.

Como los dispositivos se identifican y después envían el mensaje pues justo antes aparece el dispositivo 12345.

![][image-10]

Entonces la bandera era `flag{Sensor_12345}`


---

<br/>

## Contact Us

Obtenemos un montón de paquetes cifrados. Los decifré con el archivo que venía en Wireshark en Ajustes en la parte de Protocolos -\> TLS

Después solo buscamos algún paquete que tenga Contact Us.

Lo encontré pero no venía nada sobre Verónica, y hace todo el sentido del mundo pues eso lo sirve el host y los datos los envía la misma Verónica.

Busqué por Veronica y en uno de los objetos trasnmitidos encuentro su nombre y más abajo la bandera. 

![][image-11]


[1]:	#Info
[2]:	#Problemas-sin-resolver
[3]:	#Password-Checker
[4]:	#Turing
[5]:	#Problemas-resueltos
[6]:	#Welcome
[7]:	#poem-collection
[8]:	#checker
[9]:	#Lazy-Leaks
[10]:	#The-Magic-Modbus
[11]:	#Sonicgraphy-Fallout
[12]:	#A-Pain-in-the-BacNet
[13]:	https://ghidra-sre.org
[14]:	https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setvbuf?view=msvc-160
[15]:	https://www.exploit-db.com/docs/english/13088-explanation-of-a-remote-buffer-overflow-vulnerability.pdf
[16]:	https://en.wikipedia.org/wiki/List_of_file_signatures

[image-1]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_a007b8ccfe4d82aa30b8420dea386d58.png
[image-2]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_0fef3e700851334adf483342d3814725.png
[image-3]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_2865528d551f7fba1678ecac813aaa77.png
[image-4]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_cb4ae98e32ceabb0a203cce67e70a953.png
[image-5]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_134248275731a7b835359c2602e44d28.png
[image-6]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_4d2a493c044c57bf16817a6b5987558e.png
[image-7]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_0b65f5b96d1ca151abee5dad109d06ca.png
[image-8]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_03357664fc95b35c0b37a33372c29ca0.png
[image-9]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_84589ca7ae31d7e2b735ed9b29367416.png
[image-10]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_128223ffe2dc06e86d36e6a54b1e582c.png
[image-11]:	https://codimd.s3.shivering-isles.com/demo/uploads/upload_5f11169e81aa32c7ba5910e5374c385b.png