'use strict';

const { constants, generateKeyPairSync, publicEncrypt, privateDecrypt } = require('node:crypto');
const { TextDecoder } = require('node:util');

const OAEP_HASH = 'sha256';
const OAEP_HASH_BYTES = 32;
// Приклад з умови збережено дослівно, включно зі словом Python.
const RSA_TEXT_SAMPLE = 'Cryptography is fun and educational! Learning RSA encryption and decryption with Python helps understand public key cryptosystems.';

// Генерує відкритий і закритий RSA-ключі як об'єкти KeyObject.
function generateRsaTextKeys(modulusLength = 2048) {
  if (!Number.isInteger(modulusLength) || modulusLength < 2048) {
    throw new RangeError('Розмір RSA-ключа має бути цілим числом від 2048 біт.');
  }
  return generateKeyPairSync('rsa', { modulusLength, publicExponent: 65537 });
}

// Визначає довжину модуля RSA в байтах.
function getRsaModulusBytes(key) {
  if (!key || key.asymmetricKeyType !== 'rsa') {
    throw new TypeError('Потрібен RSA-ключ типу KeyObject.');
  }
  return Math.ceil(key.asymmetricKeyDetails.modulusLength / 8);
}

// Визначає максимальний розмір відкритого блока RSA-OAEP.
function getRsaPlaintextBlockSize(publicKey) {
  // RFC 8017: mLen <= k - 2*hLen - 2. Для 2048 біт і SHA-256 це 190 байт.
  const size = getRsaModulusBytes(publicKey) - 2 * OAEP_HASH_BYTES - 2;
  if (size <= 0) throw new RangeError('Ключ замалий для OAEP із SHA-256.');
  return size;
}

// Кодує рядок у UTF-8, не втрачаючи коректні Unicode-символи.
function textToUtf8(text) {
  if (typeof text !== 'string') throw new TypeError('Текст має бути рядком.');
  if (!text.isWellFormed()) throw new Error('Рядок містить непарний UTF-16 сурогат.');
  return Buffer.from(text, 'utf8');
}

// Декодує об'єднані байти UTF-8; зберігає також початковий BOM.
function utf8ToText(bytes) {
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}

// Ділить байти на блоки заданого розміру.
function splitBuffer(buffer, blockSize) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Потрібен Buffer.');
  if (!Number.isInteger(blockSize) || blockSize <= 0) {
    throw new RangeError('Розмір блока має бути додатним цілим числом.');
  }
  const blocks = [];
  for (let offset = 0; offset < buffer.length; offset += blockSize) {
    blocks.push(buffer.subarray(offset, offset + blockSize));
  }
  return blocks;
}

// Перетворює зашифровані байти на Base64.
function encodeBase64(bytes) {
  return bytes.toString('base64');
}

// Перевіряє канонічний Base64 і перетворює його на байти.
function decodeBase64(value) {
  // Перевірка без вкладених повторів у regex працює і на великих рядках.
  if (typeof value !== 'string' || value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value)) {
    throw new Error('Некоректний рядок Base64.');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error('Неканонічний рядок Base64.');
  return bytes;
}

// Шифрує один блок відкритим RSA-ключем.
function encryptRsaBlock(block, publicKey) {
  return publicEncrypt({
    key: publicKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: OAEP_HASH,
  }, block);
}

// Дешифрує один блок закритим RSA-ключем.
function decryptRsaBlock(block, privateKey) {
  return privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: OAEP_HASH,
  }, block);
}

// Шифрує рядок будь-якої довжини в межах доступної пам'яті, повертає Base64.
function encryptRsaText(plaintext, publicKey) {
  if (!publicKey || publicKey.type !== 'public') throw new TypeError('Потрібен відкритий ключ.');
  const bytes = textToUtf8(plaintext);
  const blocks = splitBuffer(bytes, getRsaPlaintextBlockSize(publicKey));
  const encryptedBlocks = blocks.map(block => encryptRsaBlock(block, publicKey));
  return encodeBase64(Buffer.concat(encryptedBlocks));
}

// Дешифрує Base64 у початковий UTF-8 рядок.
function decryptRsaText(ciphertextBase64, privateKey) {
  if (!privateKey || privateKey.type !== 'private') throw new TypeError('Потрібен закритий ключ.');
  const bytes = decodeBase64(ciphertextBase64);
  const blockSize = getRsaModulusBytes(privateKey);
  if (bytes.length % blockSize !== 0) throw new Error('Пошкоджена довжина RSA-шифротексту.');
  const blocks = splitBuffer(bytes, blockSize);
  const decryptedBlocks = blocks.map(block => decryptRsaBlock(block, privateKey));
  // Спочатку об'єднуємо всі байти: один UTF-8 символ може перетинати межу блоків.
  return utf8ToText(Buffer.concat(decryptedBlocks));
}

// Виводить результати завдання 4 для англійського й українського тексту.
function runTask4(plaintext = RSA_TEXT_SAMPLE) {
  const { publicKey, privateKey } = generateRsaTextKeys();
  console.log('\nЗАВДАННЯ 4. RSA для UTF-8 рядків і Base64');
  console.log('RSA: 2048 біт, OAEP: SHA-256');
  console.log('Розмір відкритого блока:', getRsaPlaintextBlockSize(publicKey), 'байт');
  const samples = [plaintext, 'Українська: Ґанок, єдність, їжак, шифрування.'];
  for (const sample of samples) {
    const ciphertext = encryptRsaText(sample, publicKey);
    const decrypted = decryptRsaText(ciphertext, privateKey);
    console.log('\nВідкритий текст:', sample);
    console.log('Шифротекст Base64:', ciphertext);
    console.log('Розшифрований текст:', decrypted);
    console.log('Перевірка:', decrypted === sample ? 'УСПІШНО' : 'ПОМИЛКА');
  }
}

module.exports = {
  RSA_TEXT_SAMPLE,
  generateRsaTextKeys,
  getRsaModulusBytes,
  getRsaPlaintextBlockSize,
  textToUtf8,
  utf8ToText,
  splitBuffer,
  encodeBase64,
  decodeBase64,
  encryptRsaBlock,
  decryptRsaBlock,
  encryptRsaText,
  decryptRsaText,
  runTask4,
};

if (require.main === module) runTask4(process.argv[2] ?? RSA_TEXT_SAMPLE);
