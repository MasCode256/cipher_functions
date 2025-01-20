const { pki, util, asn1, random, aes, cipher } = forge;

function generate_keypair() {
  return pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
}

function encode_private_key(sk) {
  util.encode64(asn1.toDer(pki.privateKeyToAsn1(sk)).getBytes());
}

function encode_public_key(pk) {
  return util.encode64(asn1.toDer(pki.publicKeyToAsn1(pk)).getBytes());
}

function decode_private_key(privateKeyBase64) {
  try {
    const privateKeyDer = util.decode64(privateKeyBase64);
    const privateKeyAsn1 = asn1.fromDer(privateKeyDer);
    return pki.privateKeyFromAsn1(privateKeyAsn1);
  } catch (error) {
    console.error("Ошибка при декодировании приватного ключа:", error);
  }
}

function decode_public_key(publicKeyBase64) {
  try {
    const publicKeyDer = util.decode64(publicKeyBase64);
    const publicKeyAsn1 = asn1.fromDer(publicKeyDer);
    return pki.publicKeyFromAsn1(publicKeyAsn1);
  } catch (error) {
    console.error("Ошибка при декодировании публичного ключа:", error);
  }
}

function encrypt(pk, str) {
  const aesKey = random.getBytesSync(16); // 128-битный ключ для AES
  const iv = random.getBytesSync(16); // Инициализационный вектор

  // Шифрование сообщения с использованием AES
  const aesCipher = cipher.createCipheriv("AES-CBC", aesKey, iv);
  aesCipher.update(forge.util.createBuffer(str, "utf8"));
  aesCipher.finish();
  const encryptedMessage = aesCipher.output;

  // Шифрование AES ключа с использованием RSA
  const encryptedKey = pk.encrypt(aesKey);
  const encryptedKeyBase64 = util.encode64(encryptedKey);

  // Кодирование зашифрованного сообщения и ключа
  const result = {
    key: encryptedKeyBase64,
    iv: util.encode64(iv),
    message: util.encode64(encryptedMessage.getBytes()),
  };

  return JSON.stringify(result); // Сериализация результата в JSON
}

function decrypt(sk, str) {
  var encryptedData = JSON.parse(str);
  // 1. Расшифровка AES ключа с использованием RSA
  const encryptedKey = util.decode64(encryptedData.key);
  const decryptedAesKey = sk.decrypt(encryptedKey);

  // 2. Расшифровка сообщения с использованием AES
  const iv = util.decode64(encryptedData.iv);
  const encryptedMessage = util.decode64(encryptedData.message);

  // Создание AES расшифровщика
  const aesDecryptor = cipher.createDecipher("AES-CBC", decryptedAesKey);
  aesDecryptor.start({ iv: iv });
  aesDecryptor.update(forge.util.createBuffer(encryptedMessage, "raw"));
  aesDecryptor.finish();

  return aesDecryptor.output.toString(); // Получаем расшифрованное сообщение в виде строки
}

function create_signature(sk, message) {
  const md = forge.md.sha256.create();
  md.update(message, "utf8");
  const signature = sk.sign(md);
  const signatureBase64 = forge.util.encode64(signature);
  console.log("Цифровая подпись (Base64):", signatureBase64);
  return signatureBase64;
}

const isBase64 = (str) => {
  const base64Pattern = /^[A-Za-z0-9+/]+={0,2}$/;
  return base64Pattern.test(str);
};

function verify_signature(pk, message, signature) {
  const md = forge.md.sha256.create();
  md.update(message, "utf8"); // Обновляем хэш с сообщением

  // Проверка на корректность введенной подписи
  if (!isBase64(signature)) {
    console.log(
      "Некорректная подпись. Убедитесь, что подпись закодирована в Base64."
    );
    return false;
  }

  try {
    // Проверка цифровой подписи
    const verified = pk.verify(
      md.digest().bytes(),
      forge.util.decode64(signature)
    );

    console.log("Подпись действительна:", verified);
    return verified;
  } catch (error) {
    console.error("Ошибка при проверке подписи:", error);
    return false;
  }
}
