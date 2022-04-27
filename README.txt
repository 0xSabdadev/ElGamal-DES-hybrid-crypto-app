Hybrid Cryptosystem
Cryptosystem Architecture

Introduction
Pada aplikasi ini dirancang sebuah hybrid cryptosystem yang menggunakan algoritma ElGamal dan DES untuk mengenkripsi pesan dan mendekripsi ciphertext. Saya menggunakan ElGamal untuk pertukaran kunci dan DES untuk enkapsulasi data. Saya memilih ElGamal karena ini adalah algoritma kunci publik, kuncinya tidak terlalu panjang, dan tidak perlu memiliki rahasia bersama untuk berkomunikasi. Saya memilih DES karena merupakan algoritma kunci simetris, dan lebih cepat daripada ElGamal karena tidak harus melakukan banyak perhitungan matematis.

How it works
Enkripsi dan dekripsi harus dilakukan pada sesi yang sama karena setiap kali aplikasi dijalankan atau dijalankan akan menghitung kunci pribadi dan kunci publik baru. Dengan kata lain, enkripsi dari sesi sebelumnya tidak akan berfungsi dalam dekripsi sesi saat ini.

Encryption Process:
Bob wants to send an encrypted message to Alice:
1.	Alice selects a short key.
2.	Cryptosystem generates a public and private key using ElGamal.
3.	Cryptosystem encrypts Alice’s short key using ElGamal and generated public key.
4.	Bob sends message.
5.	Message is then encrypted using DES and the generated public key.
6.	Cryptosystem displays the encrypted text.

Decryption Process:
Alice wants to decrypt encrypted message sent by Bob:
1.	Alice enters the cipher text generated from the encryption.
2.	Cryptosystem uses private key, prime number, and key cipher text to get Alice’s selected short key.
3.	Cryptosystem uses decrypted short key to decrypt cipher text.
4.	Cryptosystem displays the message sent.

Application

Specifications
Aplikasi ini merupakan aplikasi java yang mengimplementasikan kriptosistem menggunakan ElGamal dan DES. Saya mendapatkan tabel dan fungsi DES dari https://en.wikipedia.org/wiki/DES_supplementary_material.
Untuk Enkripsi inputnya adalah pesan dan outputnya adalah teks sandi dalam format heksadesimal.
Untuk Dekripsi inputnya adalah string heksadesimal seperti "0123adcf" dan outputnya adalah pesan yang didekripsi sebagai string.
Kunci rahasia pendek dapat diperbarui setiap saat. Jika nilai pada area teks berbeda dengan yang disimpan, maka secara otomatis akan memperbarui ke nilai baru meskipun tombol pembaruan tidak diklik. Tetapi dekripsi harus menggunakan kunci yang sama dengan yang digunakan dalam enkripsi.
Aplikasi dapat mengenkripsi dan mendekripsi beberapa kali hingga ditutup. Namun enkripsi dan dekripsi harus dilakukan pada sesi yang sama, sebelum ditutup.
Javadoc terletak di folder \dist\javadoc. Buka dist\javadoc\index.html untuk membuka halaman utama dokumentasi Java.

Instructions 
1.	Unzip File.
2.	Go to the \dist folder.
3.	Open the jar file “CIS5371_Project1.jar”.
