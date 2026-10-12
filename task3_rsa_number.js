'use strict';

const { generatePrimeSync } = require('node:crypto');

// Генерує просте число програмно; готові p та q не використовуються.
function generatePrime(bits = 32) {
  if (!Number.isInteger(bits) || bits < 16) {
    throw new RangeError('Розмір простого числа має бути цілим числом від 16 біт.');
  }
  return generatePrimeSync(bits, { bigint: true });
}

// Обчислює найбільший спільний дільник алгоритмом Евкліда.
function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

// Обчислює НСД і коефіцієнти Безу: a*x + b*y = gcd(a, b).
function extendedGcd(a, b) {
  let oldR = a;
  let r = b;
  let oldX = 1n;
  let x = 0n;
  let oldY = 0n;
  let y = 1n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldX, x] = [x, oldX - quotient * x];
    [oldY, y] = [y, oldY - quotient * y];
  }
  return { gcd: oldR, x: oldX, y: oldY };
}

// Знаходить мультиплікативне обернене число за модулем.
function modInverse(value, modulus) {
  if (typeof value !== 'bigint' || typeof modulus !== 'bigint' || modulus <= 1n) {
    throw new TypeError('Обернення потребує BigInt і модуля, більшого за 1.');
  }
  const normalized = ((value % modulus) + modulus) % modulus;
  const result = extendedGcd(normalized, modulus);
  if (result.gcd !== 1n) throw new Error('Оберненого числа за цим модулем немає.');
  return ((result.x % modulus) + modulus) % modulus;
}

// Швидко обчислює base^exponent mod modulus без втрати точності.
function modPow(base, exponent, modulus) {
  if ([base, exponent, modulus].some(value => typeof value !== 'bigint')) {
    throw new TypeError('Аргументи modPow мають бути BigInt.');
  }
  if (exponent < 0n || modulus <= 1n) throw new RangeError('Некоректний степінь або модуль.');
  let result = 1n;
  let factor = ((base % modulus) + modulus) % modulus;
  let power = exponent;
  while (power > 0n) {
    if (power % 2n === 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    power /= 2n;
  }
  return result;
}

// Генерує пару навчальних RSA-ключів (e, n) та (d, n).
function generateRsaNumberKeys(primeBits = 32) {
  const e = 65537n;
  let p;
  let q;
  let phi;
  do {
    p = generatePrime(primeBits);
    do { q = generatePrime(primeBits); } while (q === p);
    phi = (p - 1n) * (q - 1n);
  } while (e >= phi || gcd(e, phi) !== 1n);
  const n = p * q;
  const d = modInverse(e, phi);
  return { p, q, n, phi, publicKey: { e, n }, privateKey: { d, n } };
}

// Перевіряє, що число належить діапазону представників RSA.
function validateRsaNumber(value, modulus) {
  if (typeof value !== 'bigint' || typeof modulus !== 'bigint') {
    throw new TypeError('Повідомлення і модуль RSA мають бути BigInt.');
  }
  if (modulus <= 1n || value < 0n || value >= modulus) {
    throw new RangeError('Для RSA необхідно виконати 0 <= число < n.');
  }
}

// Шифрує число за формулою C = M^e mod n.
function encryptRsaNumber(message, publicKey) {
  validateRsaNumber(message, publicKey.n);
  return modPow(message, publicKey.e, publicKey.n);
}

// Дешифрує число за формулою M = C^d mod n.
function decryptRsaNumber(ciphertext, privateKey) {
  validateRsaNumber(ciphertext, privateKey.n);
  return modPow(ciphertext, privateKey.d, privateKey.n);
}

// Виводить результати завдання 3; малі числа обрані для навчальної демонстрації.
function runTask3() {
  const keys = generateRsaNumberKeys();
  const message = 100n;
  const ciphertext = encryptRsaNumber(message, keys.publicKey);
  const decrypted = decryptRsaNumber(ciphertext, keys.privateKey);
  console.log('\nЗАВДАННЯ 3. Навчальна RSA-система для числа');
  console.log('p =', keys.p.toString());
  console.log('q =', keys.q.toString());
  console.log('n = p*q =', keys.n.toString());
  console.log('phi(n) = (p-1)*(q-1) =', keys.phi.toString());
  console.log(`Відкритий ключ (e, n) = (${keys.publicKey.e}, ${keys.n})`);
  console.log(`Закритий ключ (d, n) = (${keys.privateKey.d}, ${keys.n})`);
  console.log('M =', message.toString());
  console.log('C =', ciphertext.toString());
  console.log('Розшифроване M =', decrypted.toString());
  console.log('Перевірка:', decrypted === message ? 'УСПІШНО' : 'ПОМИЛКА');
}

module.exports = {
  generatePrime,
  gcd,
  extendedGcd,
  modInverse,
  modPow,
  generateRsaNumberKeys,
  validateRsaNumber,
  encryptRsaNumber,
  decryptRsaNumber,
  runTask3,
};

if (require.main === module) runTask3();
