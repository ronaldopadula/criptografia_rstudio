# CRIPTOGRAFIA ASSIMÉTRICA

#CRIAÇÃO DE CHAVES PARA DOIS USUÁRIOS
#Criar a chave privada. keygen() gera uma chave de forma aleatória
privatekey <- keygen()
privatekey
#Criar uma chave pública. pubkey() gera uma chave publica a partir da privada.
publicKey <- pubkey(privatekey)
publicKey
#criar o par de chaves em formato de lista para facilitar
Ronaldo <- list(private_key = privatekey, public_key = publicKey)
Ronaldo
# repetindo o processo
privatekey <- keygen()
publicKey <- pubkey(privatekey)
Camilo <- list(private_key = privatekey, public_key = publicKey)
Camilo
# usuários
Ronaldo
Camilo

# Criptografando de forma simples (mesmo usuário)
msg <- serialize(iris, NULL)
msgcript <- simple_encrypt(msg, Ronaldo$public_key)
msgcript
msgdecript <- simple_decrypt(msgcript, Ronaldo$private_key)
msgdecript
identical(msg,msgdecript)

# assinatura
#criar chave privada de assinatura
signkey <- sig_keygen()
signkey
#criar uma assinatura
pubsignkey <- sig_pubkey(signkey)
pubsignkey
# Inserir no usuário
Ronaldo<-list.append(Ronaldo, sign_key = signkey, public_sign = pubsignkey)
Ronaldo

# Assinar mensagem com assinatura privada
msg <- serialize(iris, NULL)
msg
msg_sig <- sig_sign(msg, Ronaldo$sign_key)
msg_sig
# Verificar a assinatura com a assinatura pública
sig_verify(msg, msg_sig, Ronaldo$public_sign)

# Criptografia assinada
# Ronaldo envia para Camilo uma mensagem criptografada e assinada
msg <- serialize(iris, NULL)
msgcript <- auth_encrypt(msg, Ronaldo$private_key, Camilo$public_key)
msg_sig <- sig_sign(msgcript, Ronaldo$sign_key)
# Camilo verifica a assinatura
sig_verify(msgcript, msg_sig, Ronaldo$public_sign)
msgdecript<- auth_decrypt(msgcript, Camilo$private_key, Ronaldo$public_key)
msgdecript
# conferir
identical(msg,msgdecript)
#deserialização
msg2<-unserialize(msgdecript)
msg2
# conferir as mensagens
identical(iris,msg2)

# CRIPTOGRAFAR UM ARQUIVO SEM SERIALIZAÇÃO usando safer
alice <- keypair()
alice
bob <- keypair()
write.table(iris, "iris.csv")
encrypt_file("iris.csv", alice$private_key, bob$public_key, outfile = "iris_encrypted2.bin")
file.exists("iris_encrypted2.bin")
decrypt_file("iris_encrypted2.bin", bob$private_key, alice$public_key, outfile = "iris_3.csv")
file.exists("iris_3.csv")

# asymmetric case:
Ronaldo <- keypair()
Ronaldo
Camilo <- keypair()
Camilo
#RONALDO MANDA A MENSAGEM
msg <- encrypt_string("A UFF é maravilhosa", Ronaldo$private_key, Camilo$public_key)
msg
#CAMILO RECEBE A MENSAGEM
msg2 <- decrypt_string(msg, Camilo$private_key, Ronaldo$public_key)
msg2

# CERTIFICAÇÃO DIGITAL
# Exemplo: https://www.certisign.com.br/certificado-ssl
# Um certificado é um pacote de dados que identifica completamente uma entidade e é emitido por uma Autoridade de Certificação (CA) somente após essa autoridade verificar a identidade da entidade. O pacote de dados inclui a chave pública que pertence à entidade. Quando o remetente de uma mensagem assina a mensagem com sua chave privada, o destinatário da mensagem pode usar a chave pública do remetente (recuperada do certificado enviado com a mensagem ou disponível em outro lugar na rede) para verificar se o remetente é legítimo.
# Na criptografia, o X.509 é um padrão que define o formato dos certificados de chave pública. Os certificados X.509 são usados em muitos protocolos de Internet, incluindo TLS / SSL, que é a base para HTTPS, o protocolo seguro para navegar na web. Eles também são usados em aplicativos offline, como assinaturas eletrônicas.

chain <- download_ssl_cert("globo.com")
print(chain)
ocpu <- chain[[1]]
ocpu
as.list(ocpu)$subject
write_pem(ocpu)
cert_verify(chain)

chain <- download_ssl_cert("www.r-project.org", 443)
print(chain)
print(as.list(chain[[1]])$pubkey)
cert_verify(chain, ca_bundle())

