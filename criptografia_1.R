#########################################################################
#criptografia simples de uma string
texto <- "A UFF é a minha casa!"
texto

#criptografar
textencript <- rot13(texto)
textencript
#descriptografar
textdecript <- rot13(textencript)
textdecript
#verificar exatidão
identical(texto, textdecript)

#criptografar (criptografia bruta)
encriptext <- charToRaw(texto)
encriptext
#descriptografar
decriptext <- rawToChar(encriptext)
decriptext
#verificar exatidão
identical(texto, decriptext)

#########################################################################
#criptografia de hash (apenas raw)
hashtext <- hash(encriptext)
hashtext
# converte uma string de ASCII para valores exadecimais
hex <- bin2hex(hashtext)
hex
hashex <- hex2bin(hex)
hashex
identical(hashex,hashtext)
#########################################################################
#chaves ou números aleatórios
#chave com pares alfanumericos, representando bytes
chave <- random(n=5)
chave
bytes <- rand_bytes(n=5)
bytes
num <- rand_num(n=5)
num

#########################################################################
# CRIPTOGRAFIA DE UMA STRING usando safer
# symmetric case:
msg <- encrypt_string("hello, how are you", key = "secret")
msg
msg <- decrypt_string(msg, key = "secret")
msg

