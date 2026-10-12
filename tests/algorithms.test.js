'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { checkPrimeSync } = require('node:crypto');
const caesar = require('../task1_caesar');
const vigenere = require('../task2_vigenere');
const numberRsa = require('../task3_rsa_number');
const textRsa = require('../task4_rsa_text');

test('Цезар: відомий зсув, регістр і сторонні символи', () => {
  const source = 'Abc xyz! Привіт';
  const encrypted = 'Def abc! Привіт';
  assert.equal(caesar.encryptCaesar(source, 3), encrypted);
  assert.equal(caesar.decryptCaesar(encrypted, 3), source);
  assert.equal(caesar.encryptCaesar('abc', -1), 'zab');
  assert.equal(caesar.decryptCaesar('def', 29), 'abc');
  assert.throws(() => caesar.encryptCaesar('abc', 1.5));
});

test('Цезар: усі 26 ключів і розв’язок заданого шифротексту', () => {
  const candidates = caesar.bruteForceCaesar(caesar.CAESAR_CIPHERTEXT);
  assert.equal(candidates.length, 26);
  assert.equal(new Set(candidates.map(item => item.key)).size, 26);
  assert.equal(candidates.find(item => item.key === 11).plaintext, 'keepcalmandencrypt');
  assert.equal(caesar.encryptCaesar('keepcalmandencrypt', 11), caesar.CAESAR_CIPHERTEXT);
});

test('Віженер: незалежний приклад із числовими зсувами 1 і 2', () => {
  // а(0)+б(1)=б; б(1)+в(2)=г; в(2)+б(1)=г; г(3)+в(2)=д; ґ(4)+б(1)=д.
  assert.equal(vigenere.UKRAINIAN_ALPHABET.length, 33);
  assert.equal(vigenere.encryptVigenere('абвгґ', 'бв'), 'бггдд');
  assert.equal(vigenere.decryptVigenere('бггдд', 'бв'), 'абвгґ');
  assert.equal(vigenere.encryptVigenere('А ґ!Я', 'бв'), 'Б е!А');
  assert.equal(vigenere.decryptVigenere('Б е!А', 'бв'), 'А ґ!Я');
});

test('Віженер: нормалізація прикладу, повторення ключа та всі українські літери', () => {
  const source = vigenere.normalizeUkrainianText(vigenere.VIGENERE_SAMPLE);
  assert.equal(source, 'криптографічніметодизахистуінформації');
  const encrypted = vigenere.encryptVigenere(source, 'Молитовник');
  assert.equal(vigenere.decryptVigenere(encrypted, 'Молитовник'), source);
  const alphabet = vigenere.UKRAINIAN_ALPHABET + vigenere.UKRAINIAN_ALPHABET.toUpperCase();
  assert.equal(vigenere.decryptVigenere(vigenere.encryptVigenere(alphabet, 'Їґє'), 'Їґє'), alphabet);
  assert.equal(vigenere.encryptVigenere('Україна, 2026!', 'Лук’яненко'),
    vigenere.encryptVigenere('Україна, 2026!', 'лукяненко'));
  assert.equal(vigenere.decryptVigenere('', 'Ключ'), '');
  assert.throws(() => vigenere.encryptVigenere('текст', ''));
  assert.throws(() => vigenere.encryptVigenere('текст', 'Smith'));
});

test('RSA числа: незалежний відомий приклад n=3233, e=17, d=2753', () => {
  assert.equal(numberRsa.modInverse(17n, 3120n), 2753n);
  assert.equal(numberRsa.encryptRsaNumber(65n, { e: 17n, n: 3233n }), 2790n);
  assert.equal(numberRsa.decryptRsaNumber(2790n, { d: 2753n, n: 3233n }), 65n);
  assert.equal(numberRsa.modPow(2n, 0n, 17n), 1n);
  assert.throws(() => numberRsa.modInverse(2n, 4n));
});

test('RSA числа: згенеровані прості, правильні ключі, M=100 та крайові значення', () => {
  const keys = numberRsa.generateRsaNumberKeys();
  assert.equal(checkPrimeSync(keys.p), true);
  assert.equal(checkPrimeSync(keys.q), true);
  assert.notEqual(keys.p, keys.q);
  assert.equal(keys.n, keys.p * keys.q);
  assert.equal(keys.phi, (keys.p - 1n) * (keys.q - 1n));
  assert.equal(numberRsa.gcd(keys.publicKey.e, keys.phi), 1n);
  assert.equal((keys.publicKey.e * keys.privateKey.d) % keys.phi, 1n);
  for (const message of [0n, 1n, 100n, keys.p, keys.q, keys.n - 1n]) {
    const encrypted = numberRsa.encryptRsaNumber(message, keys.publicKey);
    assert.equal(numberRsa.decryptRsaNumber(encrypted, keys.privateKey), message);
  }
  assert.throws(() => numberRsa.encryptRsaNumber(keys.n, keys.publicKey));
  assert.throws(() => numberRsa.encryptRsaNumber(-1n, keys.publicKey));
  assert.throws(() => numberRsa.encryptRsaNumber(100, keys.publicKey));
  assert.throws(() => numberRsa.generatePrime(8));
});

// Одна пара ключів достатня для всіх перевірок рядкової RSA.
const textKeys = textRsa.generateRsaTextKeys();

test('RSA рядки: заданий англійський приклад і символи різних мов', () => {
  const sources = [
    textRsa.RSA_TEXT_SAMPLE,
    'Українська: Ґґ Єє Іі Її. Привіт, світе!',
    'Latin café; 中文; العربية; 日本語; Ελληνικά; е\u0301',
    '\uFEFFПочатковий BOM\u0000Нульовий байт\nНовий рядок',
    '',
  ];
  for (const source of sources) {
    const encrypted = textRsa.encryptRsaText(source, textKeys.publicKey);
    assert.equal(textRsa.decryptRsaText(encrypted, textKeys.privateKey), source);
  }
});

test('RSA рядки: межі блоків 189/190/191 байт і розриви UTF-8 символів', () => {
  assert.equal(textRsa.getRsaPlaintextBlockSize(textKeys.publicKey), 190);
  for (const source of ['a'.repeat(189), 'a'.repeat(190), 'a'.repeat(191),
    'a'.repeat(189) + 'Ї', 'a'.repeat(189)]) {
    const encrypted = textRsa.encryptRsaText(source, textKeys.publicKey);
    const blocks = Math.ceil(Buffer.byteLength(source, 'utf8') / 190);
    assert.equal(Buffer.from(encrypted, 'base64').length, blocks * 256);
    assert.equal(textRsa.decryptRsaText(encrypted, textKeys.privateKey), source);
  }
});

test('RSA рядки: довгий текст із багатьма блоками', () => {
  const source = 'Довгий UTF-8 текст, їжак і ґанок.\n'.repeat(300);
  const encrypted = textRsa.encryptRsaText(source, textKeys.publicKey);
  assert.ok(Buffer.byteLength(source, 'utf8') > 10000);
  assert.equal(textRsa.decryptRsaText(encrypted, textKeys.privateKey), source);
});

test('RSA рядки: OAEP використовує випадковість, дані відновлюються точно', () => {
  const first = textRsa.encryptRsaText('Однаковий текст', textKeys.publicKey);
  const second = textRsa.encryptRsaText('Однаковий текст', textKeys.publicKey);
  assert.notEqual(first, second);
  assert.equal(textRsa.decryptRsaText(first, textKeys.privateKey), 'Однаковий текст');
  assert.equal(textRsa.decryptRsaText(second, textKeys.privateKey), 'Однаковий текст');
});

test('RSA рядки: неправильний ключ, пошкоджені блоки та некоректні кодування', () => {
  const encrypted = textRsa.encryptRsaText('Перевірка', textKeys.publicKey);
  const wrongKeys = textRsa.generateRsaTextKeys();
  assert.throws(() => textRsa.decryptRsaText(encrypted, wrongKeys.privateKey));
  const damaged = Buffer.from(encrypted, 'base64');
  damaged[20] ^= 1;
  assert.throws(() => textRsa.decryptRsaText(damaged.toString('base64'), textKeys.privateKey));
  assert.throws(() => textRsa.decryptRsaText('%%%%', textKeys.privateKey));
  assert.throws(() => textRsa.decryptRsaText('YQ==', textKeys.privateKey));
  assert.throws(() => textRsa.decodeBase64('YR=='));
  assert.throws(() => textRsa.encryptRsaText('\uD800', textKeys.publicKey));
  const invalidUtf8 = textRsa.encryptRsaBlock(Buffer.from([0xff]), textKeys.publicKey);
  assert.throws(() => textRsa.decryptRsaText(invalidUtf8.toString('base64'), textKeys.privateKey));
});
