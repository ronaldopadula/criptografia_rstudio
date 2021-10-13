# CRIPTOGRAFIA SIMÉTRICA

###########################################################
#Criptografia com a frase secreta
# é criado um hash com a frase
key <- hash(charToRaw("Ronaldo é lindo")) 
key
#Serialização - transforma a estrutura de dados em um formato de transmissão ou armazenamento.
msg1 <- serialize(iris, NULL) 
msg1
# Encrypt with a random nonce
#cria um nonce (único e aleatório)
nonce <- random(24)
nonce
# criptografa usando a chave e o nonce
msgencript <- data_encrypt(msg1, key, nonce) 
msgencript
# descriptografa com a chave e com o noce
msg2 <- data_decrypt(msgencript, key, nonce)
msg2
# verifica se a mensagem 1 e dois são identicas
identical(msg1, msg2)
# reverte o processo de serialização
iris2 <- unserialize(msgdecript)
#verifica se os dados anteriores e o resultado são iguais.
identical(iris, iris2)
iris2

###########################################################
# Autenticação com frase secreta
key <- hash(charToRaw("Ronaldo é inteligente"))
msg <- serialize(iris, NULL)
msg
mytag <- data_tag(msg, key)
mytag
# verifica-se a integridade da autenticação recalculando o data_tag e comparando
identical(mytag, data_tag(msg, key))
# caso seja falso a verificação de autenticidade, a função stopifnot() tambḿe indocará.
stopifnot(identical(mytag, data_tag(msg, key)))

# CRIPTOGRAFIA DE UM ARQUIVO SEM SERIALIZAÇÃO usando safer
write.table(iris, "iris.csv")
encrypt_file("iris.csv", outfile = "iris_encrypted.bin" )
file.exists("iris_encrypted.bin")
readBin("iris_encrypted.bin", integer(), n = 20)
decrypt_file("iris_encrypted.bin", outfile = "iris_2.csv")
